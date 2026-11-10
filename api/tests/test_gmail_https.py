"""HTTPS submission tests use fake HTTP only. No real Google access or mail."""
import base64
import unittest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from unittest.mock import Mock, patch

import requests

from api.gmail_https import (
    API_URL, TOKEN_URL, GmailHTTPSClient, GmailHTTPSender,
    GmailConnectionUnavailable, GmailDeliveryUncertain, GmailRequestRejected,
)
from api.tests.test_outreach_batches import OutreachBase, outreach, service


def response(status=200, data=None):
    return Mock(status_code=status, json=Mock(return_value=data))


def client_with(*results):
    http = Mock()
    http.post.side_effect = [response(data={'access_token': 'private-access', 'expires_in': 3600}), *results]
    return GmailHTTPSClient('client', 'private-secret', 'private-refresh', session=http), http


def message():
    msg = EmailMessage()
    msg['From'], msg['To'], msg['Subject'] = 'rep@example.test', 'school@example.test', 'Reviewed subject'
    msg['Message-ID'] = '<stable@example.test>'
    msg['In-Reply-To'] = '<intro@example.test>'
    msg['References'] = '<intro@example.test>'
    msg.set_content('Reviewed body')
    msg.add_attachment(b'%PDF-1.4 immutable sample', maintype='application', subtype='pdf', filename='Flyer.pdf')
    return msg


class GmailClientTests(unittest.TestCase):
    def test_https_submission_preserves_reviewed_mime_pdf_and_thread_headers(self):
        client, http = client_with(response(data={'id': 'provider-id'}))
        self.assertEqual(client.send_message(message()), 'provider-id')
        refresh, send = http.post.call_args_list
        self.assertEqual(refresh.args[0], TOKEN_URL)
        self.assertEqual(send.args[0], API_URL + '/messages/send')
        self.assertEqual(send.kwargs['timeout'], (5, 15))
        self.assertFalse(send.kwargs['allow_redirects'])
        raw = base64.urlsafe_b64decode(send.kwargs['json']['raw'])
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(parsed['Message-ID'], '<stable@example.test>')
        self.assertEqual(parsed['References'], '<intro@example.test>')
        self.assertEqual(next(parsed.iter_attachments()).get_payload(decode=True), b'%PDF-1.4 immutable sample')

    def test_refresh_is_reused_until_expiry(self):
        now = [0]
        client, http = client_with(response(data={'id': 'one'}), response(data={'id': 'two'}))
        client.clock = lambda: now[0]
        client.send_message(message()); now[0] = 30; client.send_message(message())
        self.assertEqual(sum(c.args[0] == TOKEN_URL for c in http.post.call_args_list), 1)

    def test_expired_token_is_refreshed_before_submission(self):
        client, http = client_with(response(data={'id': 'one'}))
        client.access_token, client.expires_at = 'old', 0
        client.send_message(message())
        self.assertEqual(http.post.call_args_list[0].args[0], TOKEN_URL)

    def test_auth_failure_never_submits_or_exposes_secrets(self):
        for failure in (response(400, {'error': 'private-refresh'}), requests.Timeout('private-secret')):
            http = Mock(); http.post.side_effect = [failure]
            client = GmailHTTPSClient('id', 'private-secret', 'private-refresh', session=http)
            with self.assertRaises(GmailConnectionUnavailable) as caught: client.send_message(message())
            self.assertNotIn('private', str(caught.exception))
            self.assertEqual(http.post.call_count, 1)

    def test_timeout_and_provider_server_errors_are_uncertain_and_never_retried(self):
        for failure in (requests.Timeout('private-access'), requests.ConnectionError('private-access'),
                        response(500), response(503), response(408)):
            client, http = client_with(failure)
            with self.assertRaises(GmailDeliveryUncertain) as caught: client.send_message(message())
            self.assertNotIn('private-access', str(caught.exception))
            self.assertEqual(http.post.call_count, 2)

    def test_rejected_requests_do_not_retry_submission(self):
        for status in (400, 401, 403, 429, 302):
            client, http = client_with(response(status))
            with self.assertRaises(GmailRequestRejected): client.send_message(message())
            self.assertEqual(http.post.call_count, 2)

    def test_malformed_success_receipt_remains_uncertain(self):
        for data in (None, [], {}, {'id': ''}):
            client, http = client_with(response(data=data))
            with self.assertRaises(GmailDeliveryUncertain): client.send_message(message())
            self.assertEqual(http.post.call_count, 2)

    def test_malformed_refresh_does_not_send(self):
        for data in ([], {}, {'access_token': 'x', 'expires_in': '3600'}):
            http = Mock(); http.post.return_value = response(data=data)
            client = GmailHTTPSClient('id', 'secret', 'refresh', session=http)
            with self.assertRaises(GmailConnectionUnavailable): client.send_message(message())
            self.assertEqual(http.post.call_count, 1)

    def test_provider_quota_does_not_expose_response_text(self):
        client, _ = client_with(response(403, {'error': {'message': 'private-access',
            'errors': [{'reason': 'dailyLimitExceeded'}]}}))
        with self.assertRaisesRegex(GmailRequestRejected, 'quota') as caught: client.send_message(message())
        self.assertNotIn('private-access', str(caught.exception))


class GmailQueueTests(OutreachBase):
    def batch(self):
        school = self.school('HTTPS School')
        result = self.create_batch(self.owner, school_ids=[school.id], kind='custom', contact_mode=True,
            subject='Hello [school_name]', body='Hello [contact_name]', attachment_ids=[])
        self.assertEqual(result.status_code, 202, result.get_json())
        return result.get_json()['batch_id']

    def run_with(self, client):
        with patch.object(service, 'SmtpSender', side_effect=lambda email, password, name:
                          GmailHTTPSender(service, client, email, name)):
            self.run_workers()

    def test_https_sender_uses_existing_reviewed_queue_and_audit(self):
        bid = self.batch()
        client, http = client_with(response(data={'id': 'provider-id'}))
        self.run_with(client)
        row = outreach.OutreachRecipient.query.filter_by(batch_id=bid).one()
        self.assertEqual(row.status, 'sent')
        self.assertEqual(service.SentEmail.query.count(), 1)
        self.assertEqual(service.SentMessage.query.count(), 1)
        self.assertEqual(self.fake.sent, [])
        self.assertEqual(http.post.call_count, 2)

    def test_uncertain_https_submission_is_not_recorded_as_sent_or_retried(self):
        bid = self.batch()
        client, http = client_with(requests.Timeout('unknown acceptance'))
        self.run_with(client)
        row = outreach.OutreachRecipient.query.filter_by(batch_id=bid).one()
        self.assertEqual(row.status, 'unconfirmed')
        self.assertEqual(service.SentEmail.query.count(), 0)
        self.assertEqual(http.post.call_count, 2)
        self.assertEqual(self.reviewed_retry(bid).status_code, 409)

    def test_stop_after_review_blocks_https_submission(self):
        bid = self.batch()
        row = outreach.OutreachRecipient.query.filter_by(batch_id=bid).one()
        contact = service.Contact.query.filter_by(email=row.email).one()
        contact.do_not_contact = True; service.db.session.commit()
        client, http = client_with(response(data={'id': 'must-not-send'}))
        self.run_with(client)
        self.assertEqual(outreach.OutreachRecipient.query.filter_by(batch_id=bid).one().status, 'skipped')
        http.post.assert_not_called()
