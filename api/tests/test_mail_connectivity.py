import threading
import unittest
from unittest.mock import patch

from flask import Flask
from api import mail_connectivity as module


class ConnectivityTests(unittest.TestCase):
    def fixture(self):
        app = Flask(__name__)
        module.register_mail_connectivity(app)
        return app

    def test_health_metadata_is_cached_and_has_no_credentials(self):
        app = self.fixture()
        with patch.object(module, 'check_fixed_endpoints', return_value={'gmail_smtp_starttls': False}) as check:
            client = app.test_client()
            for _ in range(3):
                result = client.get('/api/health/mail-connectivity')
                self.assertEqual(result.status_code, 200)
                self.assertFalse(result.get_json()['checks']['gmail_smtp_starttls'])
            check.assert_called_once()
            self.assertEqual(client.post('/api/health/mail-connectivity').status_code, 405)

    def test_untrusted_query_does_not_change_the_probe(self):
        app = self.fixture()
        with patch.object(module, 'check_fixed_endpoints', return_value={}) as check:
            app.test_client().get('/api/health/mail-connectivity?host=evil.example&port=25')
            check.assert_called_once_with()

    def test_concurrent_checks_do_not_start_more_network_work(self):
        app = self.fixture(); entered, release = threading.Event(), threading.Event()
        def check():
            entered.set(); release.wait(2); return {}
        with patch.object(module, 'check_fixed_endpoints', side_effect=check) as probe:
            thread = threading.Thread(target=lambda: app.test_client().get('/api/health/mail-connectivity'))
            thread.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertEqual(app.test_client().get('/api/health/mail-connectivity').status_code, 202)
                self.assertEqual(probe.call_count, 1)
            finally:
                release.set(); thread.join(3)

    def test_unreachable_provider_does_not_expose_exceptions(self):
        with (patch.object(module, '_smtp', side_effect=OSError('secret internal address')),
              patch.object(module, '_tls', return_value=None)):
            result = module.check_fixed_endpoints()
            self.assertFalse(result['gmail_smtp_starttls'])
            self.assertTrue(result['gmail_imap_tls'])
            self.assertNotIn('secret', str(result))
