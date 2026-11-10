"""Gmail HTTPS transport foundation. Not selected by production sending yet.

Uses the same MIME builder and uncertain-delivery exception as the queue. OAuth
onboarding, bounded reply sync and the cloud scheduler must land before activation.
No automatic retry of a send, including on 401, timeout or provider server error.
"""
import base64
import time

import requests
from email import policy


TOKEN_URL = 'https://oauth2.googleapis.com/token'
API_URL = 'https://gmail.googleapis.com/gmail/v1/users/me'


class GmailConnectionUnavailable(RuntimeError):
    pass


class GmailRequestRejected(RuntimeError):
    pass


class GmailDeliveryUncertain(RuntimeError):
    pass


class GmailHTTPSClient:
    """A short-lived per-worker client; tokens/response bodies never enter errors."""

    def __init__(self, client_id, client_secret, refresh_token, *, session=None, clock=time.monotonic):
        if not all(isinstance(value, str) and value.strip()
                   for value in (client_id, client_secret, refresh_token)):
            raise GmailConnectionUnavailable('Google mail authorization is not configured')
        self.client_id, self.client_secret, self.refresh_token = client_id, client_secret, refresh_token
        self.http = session if session is not None else requests.Session()
        self.clock = clock
        self.access_token = None
        self.expires_at = 0

    def _authorize(self):
        if self.access_token and self.clock() < self.expires_at:
            return
        try:
            response = self.http.post(TOKEN_URL, data={
                'client_id': self.client_id, 'client_secret': self.client_secret,
                'refresh_token': self.refresh_token, 'grant_type': 'refresh_token',
            }, timeout=(5, 15), allow_redirects=False)
            if response.status_code != 200:
                raise GmailConnectionUnavailable('Reconnect Google mail authorization')
            data = response.json()
            if not isinstance(data, dict):
                raise GmailConnectionUnavailable('Google returned an invalid mail authorization')
            token, lifetime = data.get('access_token'), data.get('expires_in')
            if not isinstance(token, str) or not token or type(lifetime) is not int or lifetime < 60:
                raise GmailConnectionUnavailable('Google returned an invalid mail authorization')
        except (requests.RequestException, ValueError, TypeError):
            # Never log exception text: provider responses may contain credentials.
            raise GmailConnectionUnavailable('Google mail authorization is unavailable') from None
        self.access_token = token
        self.expires_at = self.clock() + max(1, lifetime - 30)

    def send_message(self, message):
        """Submit once. A failed refresh is safe; a failed send can be uncertain."""
        self._authorize()
        raw = base64.urlsafe_b64encode(message.as_bytes(policy=policy.SMTP)).decode('ascii')
        try:
            response = self.http.post(API_URL + '/messages/send',
                headers={'Authorization': 'Bearer ' + self.access_token},
                json={'raw': raw}, timeout=(5, 15), allow_redirects=False)
        except requests.RequestException:
            raise GmailDeliveryUncertain('Google mail delivery is unconfirmed. Check Sent mail before retrying.') from None
        status = response.status_code
        if status >= 500 or status in (408, 409):
            raise GmailDeliveryUncertain('Google mail delivery is unconfirmed. Check Sent mail before retrying.')
        if status == 401:
            self.access_token = None
            raise GmailRequestRejected('Google mail authorization expired; review before retrying')
        if status == 429:
            raise GmailRequestRejected('Google mail rate limit reached; review before retrying')
        if status == 403:
            try:
                reasons = response.json().get('error', {}).get('errors', [])
                limited = any(item.get('reason') in (
                    'rateLimitExceeded', 'userRateLimitExceeded', 'dailyLimitExceeded') for item in reasons)
            except (ValueError, AttributeError, TypeError):
                limited = False
            if limited:
                raise GmailRequestRejected('Google mail sending quota reached; review before retrying')
        if status != 200:
            raise GmailRequestRejected('Google rejected the mail request; review before retrying')
        try:
            result = response.json()
            if not isinstance(result, dict) or not isinstance(result.get('id'), str) or not result['id']:
                raise ValueError()
        except (ValueError, TypeError):
            raise GmailDeliveryUncertain('Google accepted the request without a usable receipt. Check Sent mail before retrying.') from None
        return result['id']

    def close(self):
        self.access_token = None
        self.http.close()


class GmailHTTPSender:
    """Queue sender interface with existing suppression, MIME and PDF safeguards.

    Injection is deliberate: do not route employees here until OAuth/reply-sync
    setup exists. The current production factory continues to select SMTP.
    """

    def __init__(self, svc, client, from_email, from_name):
        self.svc, self.client = svc, client
        self.from_email, self.from_name = from_email, from_name
        self.server = None

    def connect(self):
        self.client._authorize()
        self.server = self.client

    def send(self, job):
        if self.svc.contact_is_blocked(job['to_email'], independent=True):
            raise ValueError('This mailbox is marked do not contact')
        if job['pdf_files']:
            with self.svc.ATTACHMENT_SLOTS:
                return self._send(job)
        return self._send(job)

    def _send(self, job):
        message = self.svc.build_email_message(
            self.from_email, self.from_name, job['to_email'], job['subject'], job['body'],
            job['pdf_files'], in_reply_to=job.get('in_reply_to'), references=job.get('references'))
        try:
            receipt = self.client.send_message(message)
        except GmailDeliveryUncertain:
            raise self.svc.AmbiguousDelivery('Google mail delivery is unconfirmed. Check Sent mail before retrying.') from None
        job['message_id'] = message['Message-ID']
        job['provider_message_id'] = receipt
        return job['message_id']

    def reset(self):
        # Never retry a submission implicitly.
        self.server = None

    def close(self):
        self.server = None
        self.client.close()
