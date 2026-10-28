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


def fake_imap(payloads, calls=None):
    """IMAP uid() stand-in: SEARCH lists every UID; FETCH serves headers for a UID set or one full message."""
    def uid(command, *args):
        if command == 'SEARCH':
            return 'OK', [' '.join(str(key) for key in sorted(payloads)).encode()]
        if command == 'FETCH':
            wanted = [int(item) for item in args[0].split(',')]
            if calls is not None:
                calls.append(('headers' if 'HEADER.FIELDS' in args[1] else 'full', wanted))
            return 'OK', [(f'{n} (UID {n} BODY[] {{size}})'.encode(), payloads[n]) for n in wanted if n in payloads]
        raise AssertionError(command)
    return uid


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

        payloads = {1: unrelated, 2: reply}
        uid = fake_imap(payloads)

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
            mailbox.uid.side_effect = fake_imap({1: reply})
            result = service.sync_user_mailbox(self.owner)
        self.assertEqual(result['replies_found'], 1)
        self.assertTrue(result['ready'])

    def test_unthreaded_message_does_not_answer_a_tracked_conversation(self):
        message = incoming('office@maple.test', 'Unrelated update', '<unrelated-contact@test>')
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'1'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'8'])
            mailbox.uid.side_effect = fake_imap({1: message})
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
        payloads = {1: bounced, 2: own, 3: automated.as_bytes()}
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'3'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'43'])
            mailbox.uid.side_effect = fake_imap(payloads)
            result = service.sync_user_mailbox(self.owner)
        self.assertEqual(result['replies_found'], 0)
        self.assertFalse(self.sent.responded)

    def test_headers_first_and_only_replies_fetched_in_full(self):
        payloads = {n: incoming(f'news{n}@other.test', 'Newsletter', f'<n{n}@test>') for n in range(1, 251)}
        payloads[251] = incoming('assistant@maple.test', 'Re: Intro', '<late-reply@test>', '<outbound@owner.test>')
        calls = []
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'251'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'44'])
            mailbox.uid.side_effect = fake_imap(payloads, calls)
            result = service.sync_user_mailbox(self.owner)
        self.assertEqual(result['replies_found'], 1)
        self.assertTrue(result['ready'])
        self.assertEqual([wanted for kind, wanted in calls if kind == 'full'], [[251]])
        self.assertEqual(len([1 for kind, _ in calls if kind == 'headers']), 3)  # 100 + 100 + 51
        self.assertTrue(self.sent.responded)

    def test_search_starts_the_day_before_the_first_send(self):
        searches = []
        base = fake_imap({})

        def uid(command, *args):
            if command == 'SEARCH':
                searches.append(args)
            return base(command, *args)
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'0'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'45'])
            mailbox.uid.side_effect = uid
            service.sync_user_mailbox(self.owner)
        expected = (self.sent.sent_at - timedelta(days=1)).strftime('%d-%b-%Y')
        self.assertEqual(searches[0][-1], expected)

    def test_no_tracked_sends_skips_the_scan_but_checks_the_login(self):
        other = service.User.query.filter(service.User.id != self.owner.id).first()
        with patch.object(service.imaplib, 'IMAP4_SSL') as factory:
            mailbox = factory.return_value
            mailbox.select.return_value = ('OK', [b'9'])
            mailbox.response.return_value = ('UIDVALIDITY', [b'46'])
            with patch.object(service, 'user_mail_password', return_value='app-password'):
                result = service.sync_user_mailbox(other)
            mailbox.login.assert_called_once()
            mailbox.uid.assert_not_called()
        self.assertTrue(result['ready'])
        self.assertEqual(result['messages_checked'], 0)

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
