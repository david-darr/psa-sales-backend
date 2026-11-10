"""External-user OAuth with fake Google endpoints. Never opens a live account."""
import hashlib
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

from api import gmail_oauth
from api.tests.test_outreach_batches import OutreachBase, service


class GmailOAuthTests(OutreachBase):
    def setUp(self):
        super().setUp()
        env = patch.dict('os.environ', dict(GMAIL_OAUTH_ENABLED='true', GMAIL_OAUTH_CLIENT_ID='client-id',
            GMAIL_OAUTH_CLIENT_SECRET='private-client-secret',
            GMAIL_OAUTH_REDIRECT_URI='https://api.example.test/api/mail/google/callback'))
        env.start(); self.addCleanup(env.stop)
        self.post = patch.object(gmail_oauth.requests, 'post'); self.http_post = self.post.start(); self.addCleanup(self.post.stop)
        self.get = patch.object(gmail_oauth.requests, 'get'); self.http_get = self.get.start(); self.addCleanup(self.get.stop)
        self.http_post.return_value = Mock(status_code=200, json=Mock(return_value={
            'access_token': 'private-access', 'refresh_token': 'private-refresh',
            'scope': ' '.join(gmail_oauth.SCOPES)}))
        self.http_get.return_value = Mock(status_code=200, json=Mock(return_value={'emailAddress': self.owner.email}))

    def begin(self, user=None):
        result = self.client.post('/api/mail/google/connect', headers=self.auth(user or self.owner))
        self.assertEqual(result.status_code, 200, result.get_json())
        return parse_qs(urlsplit(result.get_json()['authorization_url']).query)

    def callback(self, args):
        return self.client.get('/api/mail/google/callback', query_string={'state': args['state'][0], 'code': 'private-code'})

    def test_jwt_required_and_feature_defaults_disabled(self):
        self.assertEqual(self.client.post('/api/mail/google/connect').status_code, 401)
        with patch.dict('os.environ', {'GMAIL_OAUTH_ENABLED': 'false'}):
            result = self.client.get('/api/mail/google/status', headers=self.auth(self.owner))
            self.assertEqual(result.get_json(), dict(enabled=False, authorized=False, active=False))
            self.assertEqual(self.client.post('/api/mail/google/connect', headers=self.auth(self.owner)).status_code, 503)
        self.http_post.assert_not_called()

    def test_begin_uses_pkce_and_stores_only_encrypted_verifier(self):
        args = self.begin()
        self.assertEqual(args['access_type'], ['offline'])
        self.assertEqual(args['code_challenge_method'], ['S256'])
        self.assertEqual(args['login_hint'], [self.owner.email])
        self.assertNotIn('private-client-secret', str(args))
        ticket = service.GmailAuthorization.query.one()
        verifier = service.decrypt_password(ticket.verifier_cipher)
        self.assertNotIn(verifier, ticket.verifier_cipher)
        self.assertEqual(ticket.id, hashlib.sha256(args['state'][0].encode()).hexdigest())

    def test_callback_matches_mailbox_encrypts_refresh_and_never_activates_sending(self):
        old = self.owner.email_password
        result = self.callback(self.begin())
        self.assertEqual(result.status_code, 200, result.data)
        row = service.db.session.get(service.GmailConnection, self.owner.id)
        self.assertTrue(service.is_encrypted(row.refresh_token_cipher))
        self.assertEqual(service.decrypt_password(row.refresh_token_cipher), 'private-refresh')
        self.assertFalse(row.active)
        self.assertEqual(self.owner.email_password, old)
        self.assertEqual(result.headers['Cache-Control'], 'no-store')
        self.assertEqual(result.headers['Referrer-Policy'], 'no-referrer')
        self.assertNotIn(b'private-client-secret', result.data)
        status = self.client.get('/api/mail/google/status', headers=self.auth(self.owner)).get_json()
        self.assertEqual(status['status'], 'authorized_pending_activation')
        self.assertFalse(status['active'])
        self.assertNotIn('refresh', str(status))

    def test_callback_replay_is_refused_before_google_request(self):
        args = self.begin()
        self.assertEqual(self.callback(args).status_code, 200)
        self.assertEqual(self.callback(args).status_code, 400)
        self.assertEqual(self.http_post.call_count, 1)

    def test_wrong_google_mailbox_is_not_saved(self):
        self.http_get.return_value.json.return_value = {'emailAddress': self.other.email}
        self.assertEqual(self.callback(self.begin()).status_code, 400)
        self.assertIsNone(service.db.session.get(service.GmailConnection, self.owner.id).refresh_token_cipher)

    def test_missing_read_permission_or_refresh_token_is_refused(self):
        for data in ({'access_token': 'x', 'refresh_token': 'y', 'scope': 'https://www.googleapis.com/auth/gmail.send'},
                     {'access_token': 'x', 'scope': ' '.join(gmail_oauth.SCOPES)}):
            self.http_post.return_value.json.return_value = data
            self.assertEqual(self.callback(self.begin()).status_code, 400)
        self.http_get.assert_not_called()

    def test_unknown_expired_and_superseded_states_never_contact_google(self):
        args = self.begin()
        ticket = service.GmailAuthorization.query.one(); ticket.expires_at = service.utc_now() - timedelta(seconds=1)
        service.db.session.commit()
        self.assertEqual(self.callback(args).status_code, 400)
        old = self.begin(); self.begin()
        self.assertEqual(self.callback(old).status_code, 400)
        self.assertEqual(self.callback({'state': ['unknown-state-' * 4]}).status_code, 400)
        self.http_post.assert_not_called()

    def test_disconnect_is_employee_scoped_and_invalidates_pending_flow(self):
        args = self.begin()
        self.assertEqual(self.client.post('/api/mail/google/disconnect', headers=self.auth(self.other)).status_code, 200)
        self.assertEqual(self.callback(args).status_code, 200)
        pending = self.begin()
        self.assertEqual(self.client.post('/api/mail/google/disconnect', headers=self.auth(self.owner)).status_code, 200)
        self.assertEqual(self.callback(pending).status_code, 400)
        row = service.db.session.get(service.GmailConnection, self.owner.id)
        self.assertIsNone(row.refresh_token_cipher)
        self.assertFalse(row.active)

    def test_disconnect_during_google_exchange_wins(self):
        args = self.begin()
        original_response = self.http_post.return_value
        def exchange(*_args, **_kwargs):
            result = self.client.post('/api/mail/google/disconnect', headers=self.auth(self.owner))
            self.assertEqual(result.status_code, 200)
            return original_response
        self.http_post.side_effect = exchange
        self.assertEqual(self.callback(args).status_code, 400)
        self.assertIsNone(service.db.session.get(service.GmailConnection, self.owner.id).refresh_token_cipher)

    def test_no_redirect_uri_from_untrusted_host_or_request(self):
        with patch.dict('os.environ', {'GMAIL_OAUTH_REDIRECT_URI': 'http://evil.example/callback'}):
            self.assertEqual(self.client.post('/api/mail/google/connect', headers=self.auth(self.owner)).status_code, 503)
        args = self.begin()
        self.assertEqual(args['redirect_uri'], ['https://api.example.test/api/mail/google/callback'])

    def test_provider_error_does_not_leak_error_body_or_replay_authorization_code(self):
        self.http_post.return_value = Mock(status_code=400, text='private-client-secret')
        args = self.begin()
        result = self.callback(args)
        self.assertEqual(result.status_code, 400)
        self.assertNotIn(b'private-client-secret', result.data)
        self.assertEqual(self.callback(args).status_code, 400)
        self.assertEqual(self.http_post.call_count, 1)
