"""Support reports: saved first, emailed to the owner from the reporter's mailbox, admin-only listing."""
import base64
import os
import unittest
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service  # noqa: E402


class SupportTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        self.rep = service.User(name='Casey Rep', email='casey@example.test', password_hash='x',
                                email_password=service.encrypt_password('app-password'))
        self.nomail = service.User(name='Nomail Rep', email='nomail@example.test', password_hash='x')
        self.admin = service.User(name='Ada Admin', email='ada@example.test', password_hash='x', admin=True)
        service.db.session.add_all([self.rep, self.nomail, self.admin])
        service.db.session.commit()
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def test_report_is_saved_and_sent_from_the_reporters_gmail(self):
        with patch.object(service, 'send_email_with_attachments', return_value=True) as send:
            response = self.client.post('/api/support', headers=self.auth(self.rep), json={
                'kind': 'error', 'error': 'Could not load this view.', 'page': '/schools',
                'message': 'Happened after I filtered by stage.', 'browser': 'Chrome'})
        self.assertEqual(response.status_code, 201, response.get_json())
        self.assertEqual(response.get_json()['via'], 'reporter')
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs['to_email'], 'davidmichael.darr@gmail.com')
        self.assertEqual(kwargs['from_email'], 'casey@example.test')
        self.assertIn('Could not load this view.', kwargs['body'])
        self.assertIn('/schools', kwargs['body'])
        self.assertTrue(service.SupportReport.query.one().delivered)

    def test_report_without_any_mailbox_is_kept_for_the_admin(self):
        with patch.dict(service.app.config, {'MAIL_USERNAME': None, 'MAIL_PASSWORD': None}):
            response = self.client.post('/api/support', headers=self.auth(self.nomail),
                                        json={'kind': 'question', 'message': 'How do I add a school?'})
        self.assertEqual(response.get_json()['delivered'], False)
        self.assertEqual(self.client.get('/api/support', headers=self.auth(self.rep)).status_code, 403)
        listed = self.client.get('/api/support', headers=self.auth(self.admin)).get_json()
        self.assertEqual(listed[0]['reporter'], 'Nomail Rep')
        self.assertEqual(listed[0]['subject'], 'How do I add a school?')

    def test_validation_and_hourly_limit(self):
        for body in ({}, {'kind': 'other', 'message': 'x'}, {'kind': 'bug', 'message': 5}):
            self.assertEqual(self.client.post('/api/support', headers=self.auth(self.nomail), json=body).status_code, 400)
        self.assertEqual(self.client.post('/api/support', json={'message': 'x'}).status_code, 401)
        with patch.dict(service.app.config, {'MAIL_USERNAME': None, 'MAIL_PASSWORD': None}):
            codes = [self.client.post('/api/support', headers=self.auth(self.nomail),
                                      json={'message': f'note {i}'}).status_code for i in range(11)]
        self.assertEqual(codes[:10], [201] * 10)
        self.assertEqual(codes[10], 429)


if __name__ == '__main__':
    unittest.main()
