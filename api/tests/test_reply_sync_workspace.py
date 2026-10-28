"""Mailbox cursor/threading and school ownership contract without network traffic."""

import base64
import os
import unittest
from datetime import timedelta
from email.message import EmailMessage
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())

from api import api as service  # noqa: E402


def incoming(sender, subject, message_id, reference=None):
    message = EmailMessage()
    message['From'] = sender
    message['To'] = 'owner@example.com'
    message['Subject'] = subject
    message['Message-ID'] = message_id
    if reference:
        message['In-Reply-To'] = reference
    message['Date'] = service.email.utils.format_datetime(
        service.datetime.now(service.timezone.utc)
    )
    message.set_content('Please call us about next semester.')
    return message.as_bytes()


class ReplySyncWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        service.app.config['TESTING'] = True
        cls.context = service.app.app_context()
        cls.context.push()
        service.db.create_all()
        cls.client = service.app.test_client()
        cls.owner = service.User(name='Owner', email='owner@example.com', admin=False)
        cls.other = service.User(name='Other', email='other@example.com', admin=False)
        cls.admin = service.User(name='Admin', email='admin@example.com', admin=True)
        for user in (cls.owner, cls.other, cls.admin):
            user.set_password('test-password')
        cls.owner.email_password = service.encrypt_password('test-app-password')
        service.db.session.add_all([cls.owner, cls.other, cls.admin])
        service.db.session.commit()
        cls.tokens = {user.id: service.create_access_token(identity=str(user.id))
                      for user in (cls.owner, cls.other, cls.admin)}
        cls.school = service.SalesSchool(school_name='Maple School', email='office@maple.test',
                                         school_type='preschool', user_id=cls.owner.id)
        service.db.session.add(cls.school)
        service.db.session.commit()
        cls.sent = service.SentEmail(school_name=cls.school.school_name,
                                     school_email=cls.school.email,
                                     sales_school_id=cls.school.id, user_id=cls.owner.id,
                                     sent_at=service.utc_now() - timedelta(days=8),
                                     responded=False, followup_sent=False)
        service.db.session.add(cls.sent)
        service.db.session.flush()
        service.db.session.add(service.SentMessage(sent_email_id=cls.sent.id,
                                message_id='<outbound@owner.test>', subject='Intro', kind='outreach'))
        service.db.session.commit()

    @classmethod
    def tearDownClass(cls):
        service.db.session.remove()
        service.db.drop_all()
        service.db.engine.dispose()
        cls.context.pop()

    def auth(self, user):
        return {'Authorization': f'Bearer {self.tokens[user.id]}'}

    def setUp(self):
        service.EmailReply.query.delete()
        service.MailSyncState.query.delete()
        service.SchoolActivity.query.delete()
        service.SentMessage.query.delete()
        service.db.session.add(service.SentMessage(sent_email_id=self.sent.id,
            message_id='<outbound@owner.test>', subject='Intro', kind='outreach'))
        self.school.user_id = self.owner.id
        self.school.status = 'pending'
        self.school.next_action = None
        self.school.next_action_at = None
        self.sent.responded = False
        self.sent.reply_count = 0
        self.sent.last_reply_date = None
        service.db.session.commit()

    def test_uid_cursor_exact_thread_and_followup_gate(self):
        unrelated = incoming('news@other.test', 'Hello', '<unrelated@test>')
        reply = incoming('assistant@maple.test', 'New subject', '<reply@test>',
                         '<outbound@owner.test>')
        payloads = {'1': unrelated, '2': reply}

        def uid(command, *args):
            if command == 'SEARCH':
                return 'OK', [b'1 2']
            if command == 'FETCH':
                return 'OK', [(b'2 (BODY[] {size})', payloads[args[0]])]
            raise AssertionError(command)

        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'2'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'42'])
            mailbox.uid.side_effect = uid
            first = service.sync_user_mailbox(self.owner, max_messages=1)
            self.assertFalse(first['ready'])
            self.assertEqual(first['pending_count'], 1)
            self.assertEqual(first['replies_found'], 0)
            second = service.sync_user_mailbox(self.owner, max_messages=1)
            self.assertTrue(second['ready'])
            self.assertEqual(second['replies_found'], 1)
            third = service.sync_user_mailbox(self.owner, max_messages=1)
            self.assertEqual(third['replies_found'], 0)

        service.db.session.refresh(self.sent)
        self.assertTrue(self.sent.responded)
        self.assertEqual(self.sent.reply_count, 1)
        self.assertEqual(service.EmailReply.query.filter_by(sent_email_id=self.sent.id).count(), 1)
        self.assertEqual(self.school.status, 'replied')
        state = service.db.session.get(service.MailSyncState, self.owner.id)
        self.assertEqual(state.last_uid, 2)

    def test_legacy_sender_match_without_reply_subject(self):
        service.SentMessage.query.delete()
        service.db.session.commit()
        reply = incoming('Office <office@maple.test>', 'Meeting availability', '<legacy@test>')
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'1'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'7'])
            mailbox.uid.side_effect = lambda command, *args: (
                ('OK', [b'1']) if command == 'SEARCH'
                else ('OK', [(b'1 (BODY[] {size})', reply)])
            )
            result = service.sync_user_mailbox(self.owner)
        self.assertEqual(result['replies_found'], 1)
        self.assertTrue(result['ready'])

    def test_unthreaded_message_does_not_answer_a_tracked_conversation(self):
        message = incoming('office@maple.test', 'Unrelated update', '<unrelated-contact@test>')
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'1'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'8'])
            mailbox.uid.side_effect = lambda command, *args: (
                ('OK', [b'1']) if command == 'SEARCH'
                else ('OK', [(b'1 (BODY[] {size})', message)])
            )
            result = service.sync_user_mailbox(self.owner)
        self.assertEqual(result['replies_found'], 0)
        self.assertFalse(self.sent.responded)

    def test_automatic_and_self_messages_do_not_count_as_replies(self):
        bounced = incoming('Mail Delivery <mailer-daemon@googlemail.com>',
                           'Delivery failed', '<bounce@test>', '<outbound@owner.test>')
        own = incoming(self.owner.email, 'Forwarded copy', '<self@test>',
                       '<outbound@owner.test>')
        automated = EmailMessage()
        automated['From'] = 'office@maple.test'
        automated['Subject'] = 'Automatic response'
        automated['Message-ID'] = '<automatic@test>'
        automated['In-Reply-To'] = '<outbound@owner.test>'
        automated['Auto-Submitted'] = 'auto-replied'
        automated.set_content('Away from the office')
        payloads = {b'1': bounced, b'2': own, b'3': automated.as_bytes()}
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'3'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'43'])
            mailbox.uid.side_effect = lambda command, *args: (
                ('OK', [b'1 2 3']) if command == 'SEARCH'
                else ('OK', [(b'1 (BODY[] {size})', payloads[args[0].encode()])])
            )
            result = service.sync_user_mailbox(self.owner)
        self.assertEqual(result['replies_found'], 0)
        self.assertFalse(self.sent.responded)

    def test_failed_mailbox_check_stays_blocked(self):
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory, patch.object(service.logging, 'exception'):
            factory.return_value.select.return_value = ('NO', [b''])
            with self.assertRaises(RuntimeError):
                service.sync_user_mailbox(self.owner)
        state = service.db.session.get(service.MailSyncState, self.owner.id)
        self.assertIsNotNone(state)
        self.assertFalse(service.mail_sync_status(self.owner.id)['ready'])
        self.assertIsNotNone(state.last_error)
        result = self.client.get(f'/api/followup-preview/{self.sent.id}', headers=self.auth(self.owner))
        self.assertEqual(result.status_code, 409)

    def test_unreadable_credential_invalidates_previous_sync(self):
        service.db.session.add(service.MailSyncState(
            user_id=self.owner.id, uidvalidity='1', last_uid=4,
            last_success_at=service.utc_now(), pending_count=0,
        ))
        service.db.session.commit()
        with (patch.object(service, 'user_mail_password', side_effect=
                           service.MailCredentialUnavailable('bad token')),
              patch.object(service.logging, 'exception')):
            with self.assertRaises(service.MailCredentialUnavailable):
                service.sync_user_mailbox(self.owner)
        status = service.mail_sync_status(self.owner.id)
        self.assertFalse(status['ready'])
        self.assertIn('credential', status['error'])

    def test_school_permissions_duplicate_and_timeline(self):
        other_headers = self.auth(self.other)
        owner_headers = self.auth(self.owner)
        admin_headers = self.auth(self.admin)
        path = f'/api/sales-schools/{self.school.id}'
        self.assertEqual(self.client.get(path, headers=other_headers).status_code, 404)
        self.assertEqual(self.client.patch(path, json={'status': 'meeting'}, headers=other_headers).status_code, 404)
        duplicate = self.client.post('/api/add-school', headers=other_headers,
            json={'school_name': 'Maple School', 'email': 'office@maple.test'})
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.client.patch(path, json={'user_id': self.other.id},
                                            headers=owner_headers).status_code, 403)
        updated = self.client.patch(path, headers=owner_headers,
            json={'status': 'meeting', 'next_action': 'Call director',
                  'next_action_at': '2026-10-12T00:00:00'})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()['next_action'], 'Call director')
        self.assertEqual(self.client.post(path + '/activity', headers=owner_headers,
                                         json={'kind': 'call', 'detail': 'Left voicemail'}).status_code, 201)
        timeline = self.client.get(path, headers=owner_headers).get_json()['timeline']
        self.assertTrue(any(item['kind'] == 'call' for item in timeline))
        self.assertTrue(any(item['kind'] == 'outreach' for item in timeline))
        moved = self.client.patch(path, headers=admin_headers,
                                  json={'user_id': self.other.id})
        self.assertEqual(moved.status_code, 200)
        self.assertEqual(moved.get_json()['user_id'], self.other.id)
        self.assertEqual(self.client.get(path, headers=owner_headers).status_code, 404)
        self.assertEqual(self.client.get(path, headers=other_headers).status_code, 200)


if __name__ == '__main__':
    unittest.main()
