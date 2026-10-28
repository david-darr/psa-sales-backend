"""Outreach rehaul: eligibility, limits, scoping, background batches, retry/cancel, compatibility.

SMTP is always faked; the worker is run inline instead of in a thread so tests are deterministic.
"""
import base64
import os
import smtplib
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service
from api import outreach


class FakeSMTP:
    def __init__(self, fail_for=(), disconnect_once_for=(), quota_for=()):
        self.sent, self.messages = [], []
        self.fail_for, self.quota_for = set(fail_for), set(quota_for)
        self.disconnect_once_for = set(disconnect_once_for)
        self.quit_called = False

    def send_message(self, msg, from_email, to_list):
        to = to_list[0]
        if to in self.disconnect_once_for:
            self.disconnect_once_for.discard(to)
            raise smtplib.SMTPServerDisconnected('connection dropped')
        if to in self.quota_for:
            raise smtplib.SMTPDataError(550, b'5.4.5 Daily user sending quota exceeded')
        if to in self.fail_for:
            raise smtplib.SMTPDataError(550, b'mailbox unavailable')
        self.sent.append(to)
        self.messages.append(msg)

    def rset(self):
        pass

    def quit(self):
        self.quit_called = True


class OutreachBase(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        mailbox = service.encrypt_password('dummy-app-password')
        self.owner = service.User(name='Owner', email='owner@example.test', admin=False, password_hash='x', email_password=mailbox)
        self.other = service.User(name='Other', email='other@example.test', admin=False, password_hash='x', email_password=mailbox)
        self.admin = service.User(name='Admin', email='admin@example.test', admin=True, password_hash='x', email_password=mailbox)
        self.nobox = service.User(name='NoBox', email='nobox@example.test', admin=False, password_hash='x')
        service.db.session.add_all([self.owner, self.other, self.admin, self.nobox])
        service.db.session.flush()
        self.client = service.app.test_client()
        self.fake = FakeSMTP()
        self.started = []
        env = patch.dict(os.environ, {'OUTREACH_SEND_DELAY': '0'})
        env.start()
        self.addCleanup(env.stop)
        for target, kwargs in (
            (service, {'name': 'open_smtp_connection', 'side_effect': lambda *a, **k: self.fake}),
            (outreach, {'name': 'start_worker', 'side_effect': lambda app, bid, token: self.started.append((bid, token))}),
        ):
            patcher = patch.object(target, kwargs['name'], side_effect=kwargs['side_effect'])
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def school(self, name, owner=None, email=None, status='pending', kind='preschool', contact='Pat', **extra):
        row = service.SalesSchool(
            school_name=name, email=name.lower().replace(' ', '') + '@example.test' if email is None else email,
            school_type=kind, user_id=(owner or self.owner).id, status=status, contact_name=contact, **extra)
        service.db.session.add(row)
        service.db.session.commit()
        return row

    def sent_email(self, school, days_ago, owner=None, **extra):
        record = service.SentEmail(
            school_name=school.school_name, school_email=school.email, user_id=(owner or self.owner).id,
            sales_school_id=school.id, sent_at=service.utc_now() - timedelta(days=days_ago), **extra)
        service.db.session.add(record)
        service.db.session.commit()
        return record

    def sync_ready(self, user):
        service.db.session.add(service.MailSyncState(
            user_id=user.id, last_success_at=service.utc_now(), last_checked_at=service.utc_now(), pending_count=0))
        service.db.session.commit()

    def create_batch(self, user, **body):
        return self.client.post('/api/outreach/batches', headers=self.auth(user), json=body)

    def run_workers(self):
        while self.started:
            batch_id, token = self.started.pop(0)
            outreach.run_batch(service.app, batch_id, token, delay=0)
        service.db.session.expire_all()

    def get_batch(self, user, batch_id):
        return self.client.get(f'/api/outreach/batches/{batch_id}', headers=self.auth(user)).get_json()

    def recipients(self, user, **params):
        query = '&'.join(f'{key}={value}' for key, value in params.items())
        return self.client.get('/api/outreach/recipients?' + query, headers=self.auth(user)).get_json()


class EligibilityTests(OutreachBase):
    def test_initial_list_shape_and_blockers(self):
        ok = self.school('Maple School')
        blank = self.school('Blank School', email='   ')
        replied = self.school('Replied School', status='replied')
        meeting = self.school('Meeting School', status='meeting')
        closed = self.school('Closed School', status='not_interested')
        former = self.school('Former School', status='former')
        emailed = self.school('Emailed School')
        self.sent_email(emailed, 1)
        data = self.recipients(self.owner, kind='initial')
        self.assertEqual((data['total'], data['page'], data['per_page']), (6, 1, 50))
        by_id = {item['school_id']: item for item in data['items']}
        self.assertNotIn(emailed.id, by_id)
        self.assertEqual(set(by_id[ok.id]), {
            'school_id', 'school_name', 'email', 'contact_name', 'status', 'owner_id', 'owner_name',
            'last_contacted_at', 'days_since_contact', 'followup_due_at', 'eligible', 'blockers'})
        self.assertTrue(by_id[ok.id]['eligible'])
        self.assertEqual(by_id[ok.id]['blockers'], [])
        self.assertEqual(by_id[blank.id]['blockers'], ['missing_email'])
        self.assertEqual(by_id[replied.id]['blockers'], ['replied'])
        self.assertEqual(by_id[meeting.id]['blockers'], ['replied'])
        self.assertEqual(by_id[closed.id]['blockers'], ['closed'])
        self.assertEqual(by_id[former.id]['blockers'], ['closed'])
        self.assertFalse(by_id[closed.id]['eligible'])

    def test_unsubscribed_and_missing_mailbox_blockers(self):
        quiet = self.school('Quiet School')
        service.db.session.add(service.SchoolActivity(
            sales_school_id=quiet.id, actor_id=self.owner.id, kind='unsubscribed', detail='asked to stop'))
        service.db.session.commit()
        mine = self.recipients(self.owner, kind='custom')['items'][0]
        self.assertEqual(mine['blockers'], ['unsubscribed'])
        orphan = self.school('Orphan School', owner=self.nobox)
        item = self.recipients(self.nobox, kind='custom')['items'][0]
        self.assertEqual((item['school_id'], item['blockers']), (orphan.id, ['no_mailbox']))

    def test_followup_list_only_contains_due_and_marks_blockers(self):
        due = self.school('Due School')
        self.sent_email(due, 8)
        fresh = self.school('Fresh School')
        self.sent_email(fresh, 2)
        answered = self.school('Answered School')
        self.sent_email(answered, 10, responded=True)
        done = self.school('Done School')
        self.sent_email(done, 10, followup_sent=True)
        stale = self.school('Stale School')
        self.sent_email(stale, 120)
        closed = self.school('Closed Due School', status='not_interested')
        self.sent_email(closed, 9)
        data = self.recipients(self.owner, kind='followup')
        by_id = {item['school_id']: item for item in data['items']}
        self.assertEqual(set(by_id), {due.id, closed.id})
        self.assertTrue(by_id[due.id]['eligible'])
        self.assertEqual(by_id[due.id]['days_since_contact'], 8)
        self.assertIsNotNone(by_id[due.id]['followup_due_at'])
        self.assertEqual(by_id[closed.id]['blockers'], ['closed'])

    def test_recently_contacted_blocks_custom_and_search_pages(self):
        recent = self.school('Recent School')
        self.sent_email(recent, 1)
        self.school('Quiet School')
        self.school('Quirk School')
        data = self.recipients(self.owner, kind='custom', q='qui', per_page=1, page=2)
        self.assertEqual((data['total'], len(data['items']), data['page'], data['per_page']), (2, 1, 2, 1))
        by_id = {item['school_id']: item for item in self.recipients(self.owner, kind='custom')['items']}
        self.assertEqual(by_id[recent.id]['blockers'], ['recently_contacted'])
        self.assertEqual(self.recipients(self.owner, kind='custom', stage='replied')['total'], 0)

    def test_invalid_query_parameters(self):
        for params in ('kind=bogus', 'kind=initial&page=0', 'kind=initial&per_page=999', 'kind=initial&page=x'):
            self.assertEqual(self.client.get('/api/outreach/recipients?' + params, headers=self.auth(self.owner)).status_code, 400)
        self.assertEqual(self.client.get('/api/outreach/recipients?kind=initial').status_code, 401)

    def test_list_uses_a_fixed_number_of_queries(self):
        for index in range(12):
            school = self.school(f'Bulk School {index}')
            if index % 2:
                self.sent_email(school, 9)
        counter = []
        from sqlalchemy import event
        engine = service.db.engine
        listener = lambda *args: counter.append(1)
        event.listen(engine, 'before_cursor_execute', listener)
        try:
            self.recipients(self.owner, kind='custom')
        finally:
            event.remove(engine, 'before_cursor_execute', listener)
        self.assertLessEqual(len(counter), 4)


class ScopingTests(OutreachBase):
    def test_non_admin_sees_only_own_and_admin_sees_everything(self):
        mine, theirs = self.school('Mine School'), self.school('Theirs School', owner=self.other)
        own_ids = {item['school_id'] for item in self.recipients(self.owner, kind='custom')['items']}
        self.assertEqual(own_ids, {mine.id})
        admin_items = {item['school_id']: item for item in self.recipients(self.admin, kind='custom')['items']}
        self.assertEqual(set(admin_items), {mine.id, theirs.id})
        self.assertEqual(admin_items[theirs.id]['owner_name'], 'Other')
        self.assertEqual(admin_items[theirs.id]['blockers'], ['not_owner'])
        self.assertEqual(self.recipients(self.admin, kind='custom', scope='mine')['total'], 0)

    def test_cannot_batch_or_preview_someone_elses_school(self):
        theirs = self.school('Theirs School', owner=self.other)
        for user in (self.owner, self.admin):
            self.assertEqual(self.create_batch(user, school_ids=[theirs.id], kind='initial').status_code, 403)
            self.assertEqual(self.client.post('/api/email-preview', headers=self.auth(user),
                json={'school_ids': [theirs.id], 'kind': 'initial'}).status_code, 403)
        self.assertEqual(self.create_batch(self.owner, school_ids=[999999], kind='initial').status_code, 403)
        self.assertEqual(outreach.OutreachBatch.query.count(), 0)

    def test_batch_visibility_cancel_and_retry_permissions(self):
        mine = self.school('Mine School')
        batch_id = self.create_batch(self.owner, school_ids=[mine.id], kind='initial').get_json()['batch_id']
        self.assertEqual(self.client.get(f'/api/outreach/batches/{batch_id}', headers=self.auth(self.other)).status_code, 404)
        self.assertEqual(self.client.post(f'/api/outreach/batches/{batch_id}/cancel', headers=self.auth(self.other)).status_code, 404)
        self.assertEqual(self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.other)).status_code, 404)
        self.assertEqual(self.client.get(f'/api/outreach/batches/{batch_id}', headers=self.auth(self.admin)).status_code, 200)
        self.assertEqual(self.client.get('/api/outreach/batches', headers=self.auth(self.other)).get_json()['items'], [])
        self.assertEqual(len(self.client.get('/api/outreach/batches', headers=self.auth(self.admin)).get_json()['items']), 1)
        self.assertEqual(self.client.get('/api/outreach/limits').status_code, 401)
        self.assertEqual(self.client.post('/api/outreach/batches', json={}).status_code, 401)


class LimitTests(OutreachBase):
    def test_default_env_override_and_usage(self):
        data = self.client.get('/api/outreach/limits', headers=self.auth(self.owner)).get_json()
        self.assertEqual((data['daily_limit'], data['sent_today'], data['remaining'], data['mailbox_connected']),
                         (150, 0, 150, True))
        self.assertTrue(data['resets_at'].startswith((service.utc_now() + timedelta(days=1)).date().isoformat()))
        school = self.school('Maple School')
        self.sent_email(school, 0)
        self.sent_email(school, 3)
        followup = self.sent_email(school, 0)
        service.db.session.add(service.SentMessage(sent_email_id=followup.id, message_id='<f@x>', subject='s', kind='followup'))
        service.db.session.commit()
        with patch.dict(os.environ, {'OUTREACH_DAILY_LIMIT': '10'}):
            data = self.client.get('/api/outreach/limits', headers=self.auth(self.owner)).get_json()
        self.assertEqual((data['daily_limit'], data['sent_today'], data['remaining']), (10, 3, 7))
        with patch.dict(os.environ, {'OUTREACH_DAILY_LIMIT': 'nonsense'}):
            self.assertEqual(self.client.get('/api/outreach/limits', headers=self.auth(self.owner)).get_json()['daily_limit'], 150)
        self.assertFalse(self.client.get('/api/outreach/limits', headers=self.auth(self.nobox)).get_json()['mailbox_connected'])
        self.assertEqual(self.client.get('/api/outreach/limits', headers=self.auth(self.other)).get_json()['sent_today'], 0)

    def test_batch_is_trimmed_with_explicit_reason_and_rejected_when_exhausted(self):
        schools = [self.school(f'Limit School {index}') for index in range(3)]
        ids = [item.id for item in schools]
        with patch.dict(os.environ, {'OUTREACH_DAILY_LIMIT': '2'}):
            response = self.create_batch(self.owner, school_ids=ids, kind='initial')
            self.assertEqual(response.status_code, 202)
            body = response.get_json()
            self.assertEqual(body['skipped'], [{'school_id': ids[2], 'reason': 'daily_limit'}])
            self.assertEqual(body['total'], 3)
            # queued recipients are reserved, so a second batch cannot overshoot the limit
            more = self.school('Limit School 4')
            again = self.create_batch(self.owner, school_ids=[more.id], kind='initial')
            self.assertEqual(again.status_code, 429)
            self.assertEqual(again.get_json()['code'], 'daily_limit')
            self.assertEqual(again.get_json()['remaining'], 0)
            self.run_workers()
            self.assertEqual(self.fake.sent, [item.email for item in schools[:2]])
            self.assertEqual(self.create_batch(self.owner, school_ids=[more.id], kind='initial').status_code, 429)

    def test_worker_rechecks_limit_before_every_send(self):
        schools = [self.school(f'Late School {index}') for index in range(2)]
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        for _ in range(150):
            service.db.session.add(service.SentEmail(school_name='x', school_email='x@example.test', user_id=self.owner.id))
        service.db.session.commit()
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual([item['status'] for item in data['recipients']], ['skipped', 'skipped'])
        self.assertEqual({item['error'] for item in data['recipients']}, {'daily_limit'})
        self.assertEqual(self.fake.sent, [])


class BatchLifecycleTests(OutreachBase):
    def test_happy_path_logs_sends_and_advances_pending_only(self):
        pending = self.school('Pending School', kind='preschool')
        contacted = self.school('Contacted School', status='contacted', kind='elementary')
        response = self.create_batch(self.owner, school_ids=[pending.id, contacted.id], kind='custom',
                                     subject='Hello [school_name]', body='Hi [contact_name], from [user_name]')
        self.assertEqual(response.status_code, 202)
        created = response.get_json()
        self.assertEqual((created['status'], created['total'], created['skipped']), ('queued', 2, []))
        queued = self.get_batch(self.owner, created['batch_id'])
        self.assertEqual(queued['status'], 'queued')
        self.assertEqual(queued['sent'], 0)
        self.run_workers()
        data = self.get_batch(self.owner, created['batch_id'])
        self.assertEqual(set(data), {'id', 'kind', 'status', 'total', 'sent', 'failed', 'skipped', 'created_at',
                                     'finished_at', 'recipients', 'queued', 'sending', 'cancelled', 'unconfirmed', 'user_id', 'owner_name'})
        self.assertEqual((data['status'], data['kind'], data['total'], data['sent'], data['failed'], data['skipped']),
                         ('done', 'custom', 2, 2, 0, 0))
        self.assertIsNotNone(data['finished_at'])
        self.assertEqual(set(data['recipients'][0]), {'school_id', 'school_name', 'email', 'status', 'error', 'sent_at'})
        self.assertEqual(self.fake.sent, [pending.email, contacted.email])
        self.assertEqual(self.fake.messages[0]['Subject'], 'Hello Pending School')
        self.assertIn('Hi Pat, from Owner', self.fake.messages[0].get_payload(0).get_payload(0).get_payload(decode=True).decode())
        self.assertEqual(self.fake.messages[0]['From'], 'Owner <owner@example.test>')
        service.db.session.refresh(pending)
        self.assertEqual(pending.status, 'contacted')
        emails = service.SentEmail.query.order_by(service.SentEmail.id).all()
        self.assertEqual([item.sales_school_id for item in emails], [pending.id, contacted.id])
        self.assertEqual(service.SentMessage.query.filter_by(kind='outreach').count(), 2)
        recipient = outreach.OutreachRecipient.query.first()
        self.assertEqual((recipient.sent_email_id, recipient.attempts), (emails[0].id, 1))
        self.assertTrue(self.fake.quit_called)
        listing = self.client.get('/api/outreach/batches?limit=10', headers=self.auth(self.owner)).get_json()
        self.assertEqual([item['id'] for item in listing['items']], [created['batch_id']])
        self.assertNotIn('recipients', listing['items'][0])

    def test_initial_uses_existing_template_and_attachments(self):
        school = self.school('Template School', kind='private', contact='Dana')
        self.create_batch(self.owner, school_ids=[school.id], kind='initial')
        self.run_workers()
        message = self.fake.messages[0]
        self.assertEqual(message['Subject'], "Let's Connect! PSA Programs")
        expected = service.render_email_text(
            service.PRIVATE_SCHOOL_EMAIL_TEMPLATE, user_name='Owner', user_email='owner@example.test',
            school_name='Template School', contact_name='Dana')
        recipient = outreach.OutreachRecipient.query.one()
        self.assertEqual(recipient.body, expected)
        self.assertEqual(recipient.attachments, '["PSA After School.pdf", "PSA Recommendation (St. Theresa).pdf"]')
        bare = self.school('Bare School')
        self.create_batch(self.owner, school_ids=[bare.id], kind='initial', attachments=False)
        self.assertEqual(outreach.OutreachRecipient.query.filter_by(school_id=bare.id).one().attachments, '[]')

    def test_one_failure_never_aborts_the_batch_and_retry_requeues_only_failed(self):
        schools = [self.school(f'Batch School {index}') for index in range(3)]
        self.fake.fail_for = {schools[1].email}
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['sent'], data['failed']), ('done', 2, 1))
        statuses = {item['school_id']: item for item in data['recipients']}
        self.assertEqual(statuses[schools[1].id]['status'], 'failed')
        self.assertIn('mailbox unavailable', statuses[schools[1].id]['error'])
        self.assertIsNone(statuses[schools[0].id]['error'])
        self.assertEqual(service.SentEmail.query.count(), 2)
        service.db.session.refresh(schools[1])
        self.assertEqual(schools[1].status, 'pending')

        self.fake.fail_for = set()
        retried = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner))
        self.assertEqual(retried.status_code, 202)
        self.assertEqual(retried.get_json()['requeued'], 1)
        self.assertEqual(self.get_batch(self.owner, batch_id)['status'], 'queued')
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['sent'], data['failed']), ('done', 3, 0))
        self.assertEqual(self.fake.sent.count(schools[0].email), 1)  # sent recipients were never resent
        self.assertEqual(outreach.OutreachRecipient.query.filter_by(school_id=schools[1].id).one().attempts, 2)
        again = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner))
        self.assertEqual(again.status_code, 409)

    def test_retry_rechecks_the_daily_limit(self):
        schools = [self.school(f'Retry School {index}') for index in range(3)]
        self.fake.fail_for = {item.email for item in schools}
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        self.run_workers()
        self.fake.fail_for = set()
        with patch.dict(os.environ, {'OUTREACH_DAILY_LIMIT': '2'}):
            result = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner))
        self.assertEqual(result.status_code, 202)
        self.assertEqual(result.get_json()['requeued'], 2)
        self.assertEqual(result.get_json()['not_retried'], [{'school_id': schools[2].id, 'reason': 'daily_limit'}])
        with patch.dict(os.environ, {'OUTREACH_DAILY_LIMIT': '1'}):
            self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual(data['sent'], 1)
        self.assertEqual(data['skipped'], 1)

    def test_cancel_marks_queued_cancelled_and_worker_sends_nothing(self):
        schools = [self.school(f'Cancel School {index}') for index in range(3)]
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        cancelled = self.client.post(f'/api/outreach/batches/{batch_id}/cancel', headers=self.auth(self.owner))
        self.assertEqual((cancelled.status_code, cancelled.get_json()['cancelled']), (200, 3))
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['cancelled'], data['sent']), ('cancelled', 3, 0))
        self.assertEqual(self.fake.sent, [])
        self.assertEqual(self.client.post(f'/api/outreach/batches/{batch_id}/cancel', headers=self.auth(self.owner)).status_code, 200)

    def test_cancel_while_in_flight_lets_current_send_finish_then_stops(self):
        schools = [self.school(f'Flight School {index}') for index in range(3)]
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        original = self.fake.send_message

        def send_then_cancel(msg, from_email, to_list):
            original(msg, from_email, to_list)
            self.client.post(f'/api/outreach/batches/{batch_id}/cancel', headers=self.auth(self.owner))
        self.fake.send_message = send_then_cancel
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['sent'], data['cancelled']), ('cancelled', 1, 2))
        self.assertEqual(self.fake.sent, [schools[0].email])

    def test_cancel_finished_batch_is_rejected(self):
        school = self.school('Done School')
        batch_id = self.create_batch(self.owner, school_ids=[school.id], kind='initial').get_json()['batch_id']
        self.run_workers()
        self.assertEqual(self.client.post(f'/api/outreach/batches/{batch_id}/cancel', headers=self.auth(self.owner)).status_code, 409)

    def test_stalled_batch_is_reported_and_retryable_and_old_worker_is_fenced_off(self):
        schools = [self.school(f'Stall School {index}') for index in range(2)]
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        old_token = self.started[0][1]
        batch = outreach.OutreachBatch.query.get(batch_id)
        batch.status = 'sending'
        batch.heartbeat_at = service.utc_now() - timedelta(minutes=16)
        first = outreach.OutreachRecipient.query.filter_by(school_id=schools[0].id).one()
        first.status = 'sending'
        service.db.session.commit()
        self.started.clear()
        self.assertEqual(self.get_batch(self.owner, batch_id)['status'], 'stalled')
        self.assertEqual(self.client.get('/api/outreach/batches', headers=self.auth(self.owner)).get_json()['items'][0]['status'], 'stalled')
        retried = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner))
        self.assertEqual((retried.status_code, retried.get_json()['requeued']), (202, 1))
        new_token = self.started[0][1]
        self.assertNotEqual(old_token, new_token)
        outreach.run_batch(service.app, batch_id, old_token, delay=0)  # a zombie from before the retry
        self.assertEqual(self.fake.sent, [])
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['sent'], data['unconfirmed']), ('done', 1, 1))
        self.assertEqual(self.fake.sent, [schools[1].email])

    def test_active_batch_is_not_retryable_and_fresh_sending_is_not_stalled(self):
        school = self.school('Busy School')
        batch_id = self.create_batch(self.owner, school_ids=[school.id], kind='initial').get_json()['batch_id']
        self.assertEqual(self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner)).status_code, 409)
        batch = outreach.OutreachBatch.query.get(batch_id)
        batch.status, batch.heartbeat_at = 'sending', service.utc_now() - timedelta(minutes=14)
        service.db.session.commit()
        self.assertEqual(self.get_batch(self.owner, batch_id)['status'], 'sending')

    def test_connection_dropped_mid_send_is_unconfirmed_not_resent(self):
        schools = [self.school(f'Drop School {index}') for index in range(2)]
        self.fake.disconnect_once_for = {schools[0].email}
        with patch.object(service, 'open_smtp_connection', side_effect=lambda *a, **k: self.fake) as opener:
            batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
            self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['sent'], data['unconfirmed'], data['failed']), ('done', 1, 1, 0))
        self.assertEqual(self.fake.sent, [schools[1].email])
        self.assertIn('unconfirmed', data['recipients'][0]['error'])
        self.assertEqual(opener.call_count, 2)

        retry = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner))
        self.assertEqual((retry.status_code, retry.get_json()['code']), (409, 'nothing_to_retry'))
        with patch.object(service, 'open_smtp_connection', side_effect=lambda *a, **k: self.fake):
            retry = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner),
                                     json={'include_unconfirmed': True})
            self.assertEqual((retry.status_code, retry.get_json()['requeued']), (202, 1))
            self.run_workers()
        self.assertEqual(self.get_batch(self.owner, batch_id)['sent'], 2)

    def test_attachment_is_encoded_once_and_arrives_intact(self):
        pdf_dir = os.path.join(os.path.dirname(service.__file__), 'pdf_attachments')
        name = sorted(f for f in os.listdir(pdf_dir) if f.lower().endswith('.pdf'))[0]
        path = os.path.join(pdf_dir, name)
        service._ENCODED_PDFS.clear()
        with patch.object(service.base64, 'encodebytes', wraps=base64.encodebytes) as encode:
            messages = [service.build_email_message('a@x.com', 'A', f'{i}@y.com', 's', 'b', [name]) for i in range(3)]
        self.assertEqual(encode.call_count, 1)
        with open(path, 'rb') as handle:
            original = handle.read()
        for msg in messages:
            part = [p for p in msg.walk() if p.get_filename() == name][0]
            self.assertEqual(part['Content-Transfer-Encoding'], 'base64')
            self.assertEqual(part.get_payload(decode=True), original)
        self.assertIsNone(service.encoded_pdf_payload(os.path.join(pdf_dir, 'missing.pdf')))

    def test_attachment_cache_refreshes_when_the_file_changes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'a.pdf')
            with open(path, 'wb') as handle:
                handle.write(b'first')
            first = service.encoded_pdf_payload(path)
            with open(path, 'wb') as handle:
                handle.write(b'second version')
            self.assertNotEqual(service.encoded_pdf_payload(path), first)

    def test_idle_connection_is_checked_and_reopened_before_sending(self):
        class StaleConnection(FakeSMTP):
            def noop(self):
                raise smtplib.SMTPServerDisconnected('idle timeout')
        stale, fresh = StaleConnection(), FakeSMTP()
        with patch.object(service, 'open_smtp_connection', side_effect=[stale, fresh]) as opener:
            sender = service.SmtpSender('owner@example.test', 'pw', 'Owner')
            sender.connect()
            sender.last_used -= 60
            sender.send({'to_email': 'a@school.test', 'subject': 's', 'body': 'b', 'pdf_files': []})
        self.assertEqual((stale.sent, fresh.sent, opener.call_count), ([], ['a@school.test'], 2))

    def test_school_already_in_an_unfinished_batch_cannot_be_queued_again(self):
        school = self.school('Busy School Twice')
        with patch.object(outreach, 'start_worker'):
            first = self.create_batch(self.owner, school_ids=[school.id], kind='initial')
            second = self.create_batch(self.owner, school_ids=[school.id], kind='initial')
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 400)
        self.assertEqual(second.get_json()['skipped'][0]['reason'], 'in_flight')

    def test_stalled_batch_does_not_resend_the_email_that_was_in_flight(self):
        schools = [self.school(f'Stall School {index}') for index in range(3)]
        with patch.object(outreach, 'start_worker'):
            batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        recipients = outreach.OutreachRecipient.query.filter_by(batch_id=batch_id).order_by(outreach.OutreachRecipient.position).all()
        recipients[0].status = 'sending'
        batch = outreach.OutreachBatch.query.get(batch_id)
        batch.status, batch.heartbeat_at = 'sending', service.utc_now() - timedelta(minutes=20)
        service.db.session.commit()
        retry = self.client.post(f'/api/outreach/batches/{batch_id}/retry', headers=self.auth(self.owner))
        self.assertEqual((retry.status_code, retry.get_json()['requeued']), (202, 2))
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['sent'], data['unconfirmed']), (2, 1))
        self.assertNotIn(schools[0].email, self.fake.sent)

    def test_login_failure_fails_every_recipient_without_hammering(self):
        schools = [self.school(f'Login School {index}') for index in range(3)]
        with patch.object(service, 'open_smtp_connection', side_effect=smtplib.SMTPAuthenticationError(535, b'bad credentials')) as opener:
            batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
            self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['failed'], data['sent']), ('done', 3, 0))
        self.assertIn('SMTP login failed', data['recipients'][2]['error'])
        self.assertEqual(opener.call_count, 1)

    def test_provider_quota_stops_the_batch_but_stays_retryable(self):
        schools = [self.school(f'Quota School {index}') for index in range(3)]
        self.fake.quota_for = {schools[1].email}
        batch_id = self.create_batch(self.owner, school_ids=[item.id for item in schools], kind='initial').get_json()['batch_id']
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['sent'], data['failed']), (1, 2))
        self.assertIn('limit', data['recipients'][2]['error'])
        self.assertEqual(self.fake.sent, [schools[0].email])

    def test_unreadable_mail_password_fails_cleanly(self):
        school = self.school('Locked School')
        batch_id = self.create_batch(self.owner, school_ids=[school.id], kind='initial').get_json()['batch_id']
        with patch.object(service, 'user_mail_password', side_effect=service.MailCredentialUnavailable('nope')):
            self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['status'], data['failed']), ('done', 1))
        self.assertIn('Email connection unavailable', data['recipients'][0]['error'])
        self.assertEqual(self.fake.sent, [])

    def test_validation_errors(self):
        school = self.school('Valid School')
        for body in ({}, {'school_ids': [], 'kind': 'initial'}, {'school_ids': ['1'], 'kind': 'initial'},
                     {'school_ids': [school.id]}, {'school_ids': [school.id], 'kind': 'weird'},
                     {'school_ids': [school.id], 'kind': 'custom'},
                     {'school_ids': [school.id], 'kind': 'custom', 'subject': 'a\nb', 'body': 'x'},
                     {'school_ids': [school.id], 'kind': 'initial', 'attachments': 'yes'},
                     {'school_ids': list(range(1, 502)), 'kind': 'initial'}):
            self.assertEqual(self.create_batch(self.owner, **body).status_code, 400, body)
        self.assertEqual(self.create_batch(self.nobox, school_ids=[school.id], kind='initial').status_code, 400)
        self.assertEqual(outreach.OutreachBatch.query.count(), 0)


class SafetyRuleTests(OutreachBase):
    def test_blank_and_invalid_emails_are_skipped_with_reason(self):
        good = self.school('Good School')
        blank = self.school('Blank School', email='')
        invalid = self.school('Invalid School', email='not-an-email')
        body = self.create_batch(self.owner, school_ids=[good.id, blank.id, invalid.id], kind='initial').get_json()
        self.assertEqual(body['skipped'], [{'school_id': blank.id, 'reason': 'missing_email'},
                                           {'school_id': invalid.id, 'reason': 'missing_email'}])
        self.run_workers()
        data = self.get_batch(self.owner, body['batch_id'])
        self.assertEqual((data['total'], data['sent'], data['skipped'], data['status']), (3, 1, 2, 'done'))
        self.assertEqual(self.fake.sent, [good.email])
        only_blank = self.create_batch(self.owner, school_ids=[blank.id], kind='initial')
        self.assertEqual(only_blank.status_code, 400)
        self.assertEqual(only_blank.get_json()['skipped'], [{'school_id': blank.id, 'reason': 'missing_email'}])

    def test_falls_back_to_a_valid_additional_email(self):
        school = self.school('Backup School', email='')
        school.set_additional_emails(['office@backup.example.test'])
        service.db.session.commit()
        self.create_batch(self.owner, school_ids=[school.id], kind='initial')
        self.run_workers()
        self.assertEqual(self.fake.sent, ['office@backup.example.test'])

    def test_replied_closed_and_recent_schools_are_skipped_not_sent(self):
        replied = self.school('Replied School', status='replied')
        closed = self.school('Closed School', status='former')
        recent = self.school('Recent School')
        self.sent_email(recent, 0)
        fine = self.school('Fine School')
        body = self.create_batch(self.owner, school_ids=[replied.id, closed.id, recent.id, fine.id], kind='custom',
                                 subject='Hi', body='Hello').get_json()
        self.assertEqual({item['school_id']: item['reason'] for item in body['skipped']},
                         {replied.id: 'replied', closed.id: 'closed', recent.id: 'recently_contacted'})
        self.run_workers()
        self.assertEqual(self.fake.sent, [fine.email])

    def test_status_is_never_downgraded_by_a_send(self):
        for stage in ('replied', 'meeting', 'partner', 'former', 'not_interested'):
            self.assertEqual(self.create_batch(self.owner, school_ids=[self.school(f'{stage} school', status=stage).id],
                                               kind='custom', subject='s', body='b').status_code, 400)
        contacted = self.school('Contacted School', status='contacted')
        self.create_batch(self.owner, school_ids=[contacted.id], kind='custom', subject='s', body='b')
        self.run_workers()
        service.db.session.refresh(contacted)
        self.assertEqual(contacted.status, 'contacted')
        pending = self.school('Pending School')
        self.create_batch(self.owner, school_ids=[pending.id], kind='custom', subject='s', body='b')
        self.run_workers()
        service.db.session.refresh(pending)
        self.assertEqual(pending.status, 'contacted')

    def test_status_change_after_queueing_skips_the_send(self):
        school = self.school('Racing School')
        batch_id = self.create_batch(self.owner, school_ids=[school.id], kind='initial').get_json()['batch_id']
        school.status = 'replied'
        service.db.session.commit()
        self.run_workers()
        data = self.get_batch(self.owner, batch_id)
        self.assertEqual((data['recipients'][0]['status'], data['recipients'][0]['error']), ('skipped', 'replied'))
        self.assertEqual(self.fake.sent, [])
        service.db.session.refresh(school)
        self.assertEqual(school.status, 'replied')

    def test_old_send_endpoint_no_longer_downgrades_replied(self):
        school = self.school('Replied Old School', status='replied')
        pending = self.school('Pending Old School')
        with patch.object(service, 'send_emails_over_connection',
                          side_effect=lambda _a, _b, _c, jobs: [(job, True, None) for job in jobs]):
            response = self.client.post('/api/send-email', headers=self.auth(self.owner),
                                        json={'school_ids': [school.id, pending.id]})
        self.assertEqual(response.status_code, 200)
        service.db.session.expire_all()
        self.assertEqual(service.db.session.get(service.SalesSchool, school.id).status, 'replied')
        self.assertEqual(service.db.session.get(service.SalesSchool, pending.id).status, 'contacted')

    def test_followup_batch_threads_marks_followup_sent_and_requires_fresh_inbox(self):
        school = self.school('Follow School', status='contacted')
        original = self.sent_email(school, 9)
        service.db.session.add(service.SentMessage(sent_email_id=original.id, message_id='<orig@owner.test>',
                                                   subject='Hello', kind='outreach',
                                                   sent_at=service.utc_now() - timedelta(days=9)))
        service.db.session.commit()
        stale = self.create_batch(self.owner, school_ids=[school.id], kind='followup')
        self.assertEqual((stale.status_code, stale.get_json()['code']), (409, 'inbox_not_synced'))
        self.sync_ready(self.owner)
        response = self.create_batch(self.owner, school_ids=[school.id], kind='followup')
        self.assertEqual(response.status_code, 202)
        self.run_workers()
        data = self.get_batch(self.owner, response.get_json()['batch_id'])
        self.assertEqual((data['status'], data['sent']), ('done', 1))
        message = self.fake.messages[0]
        self.assertEqual(message['Subject'], service.FOLLOWUP_SUBJECT)
        self.assertEqual(message['In-Reply-To'], '<orig@owner.test>')
        self.assertEqual(message.get_payload()[-1].get_content_type(), 'multipart/alternative')  # no attachments
        service.db.session.refresh(original)
        self.assertTrue(original.followup_sent)
        self.assertEqual(service.SentEmail.query.count(), 1)
        self.assertEqual(service.SentMessage.query.filter_by(kind='followup').count(), 1)
        self.assertEqual(self.create_batch(self.owner, school_ids=[school.id], kind='followup').status_code, 400)

    def test_followup_not_due_is_skipped(self):
        self.sync_ready(self.owner)
        school = self.school('Early School')
        self.sent_email(school, 2)
        result = self.create_batch(self.owner, school_ids=[school.id], kind='followup')
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.get_json()['skipped'][0]['reason'], 'recently_contacted')


class PreviewTests(OutreachBase):
    def test_new_preview_shape_warnings_and_token_reuse(self):
        ok = self.school('Preview School', contact='')
        blank = self.school('Blank Preview', email='')
        replied = self.school('Replied Preview', status='replied')
        closed = self.school('Closed Preview', status='not_interested')
        recent = self.school('Recent Preview')
        self.sent_email(recent, 0)
        ids = [ok.id, blank.id, replied.id, closed.id, recent.id]
        response = self.client.post('/api/email-preview', headers=self.auth(self.owner),
                                    json={'school_ids': ids, 'kind': 'initial', 'subject': 'Hi [school_name]'})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['preview_token'])
        previews = {item['school_id']: item for item in data['previews']}
        self.assertEqual(set(previews[ok.id]), {'school_id', 'school_name', 'email', 'subject', 'body_html', 'body_text',
                                                 'warnings', 'attachments', 'eligible', 'blockers'})
        self.assertEqual(previews[ok.id]['subject'], 'Hi Preview School')
        self.assertEqual(previews[ok.id]['warnings'], ['empty_greeting'])
        self.assertIn('Director/Administrator', previews[ok.id]['body_text'])
        self.assertIn('<html>', previews[ok.id]['body_html'])
        self.assertEqual(previews[blank.id]['warnings'], ['missing_email'])
        self.assertEqual(previews[replied.id]['warnings'], ['replied'])
        self.assertEqual(previews[closed.id]['warnings'], ['closed'])
        self.assertEqual(previews[recent.id]['warnings'], ['recently_contacted'])
        sent = self.create_batch(self.owner, school_ids=[ok.id], kind='initial', subject='Hi [school_name]',
                                 preview_token=data['preview_token'])
        self.assertEqual(sent.status_code, 202)

    def test_batch_rejects_stale_or_foreign_token_but_accepts_no_token(self):
        school = self.school('Token School')
        token = self.client.post('/api/email-preview', headers=self.auth(self.owner),
                                 json={'school_ids': [school.id], 'kind': 'initial'}).get_json()['preview_token']
        changed = self.create_batch(self.owner, school_ids=[school.id], kind='initial', body='A different body',
                                    preview_token=token)
        self.assertEqual(changed.status_code, 409)
        self.assertEqual(self.create_batch(self.owner, school_ids=[school.id], kind='initial', preview_token='garbage').status_code, 409)
        self.assertEqual(self.create_batch(self.owner, school_ids=[school.id], kind='initial', preview_token=5).status_code, 400)
        self.assertEqual(outreach.OutreachBatch.query.count(), 0)
        self.assertEqual(self.create_batch(self.owner, school_ids=[school.id], kind='initial').status_code, 202)

    def test_followup_preview_uses_existing_followup_template(self):
        school = self.school('Follow Preview')
        original = self.sent_email(school, 9)
        data = self.client.post('/api/email-preview', headers=self.auth(self.owner),
                                json={'school_ids': [school.id], 'kind': 'followup'}).get_json()
        item = data['previews'][0]
        self.assertEqual(item['subject'], service.FOLLOWUP_SUBJECT)
        self.assertEqual(item['body_text'].strip(), service.render_body_parts(service.followup_message(self.owner, original))[0].strip())
        self.assertEqual(item['warnings'], [])

    def test_preview_validation(self):
        school = self.school('Check School')
        for body in ({'school_ids': [school.id], 'kind': 'nope'}, {'school_ids': [], 'kind': 'initial'},
                     {'school_ids': [school.id], 'kind': 'custom'}):
            self.assertEqual(self.client.post('/api/email-preview', headers=self.auth(self.owner), json=body).status_code, 400)


class BackwardCompatibilityTests(OutreachBase):
    def test_old_preview_shape_is_unchanged(self):
        school = self.school('Old Preview School')
        data = self.client.post('/api/email-preview', headers=self.auth(self.owner),
                                json={'school_ids': [school.id], 'send_to_all_emails': False}).get_json()
        self.assertEqual(set(data), {'preview_token', 'items'})
        self.assertEqual(set(data['items'][0]), {'school_id', 'school_name', 'to_email', 'subject', 'body', 'attachments'})
        self.assertEqual(data['items'][0]['to_email'], school.email)
        self.assertEqual(self.client.post('/api/email-preview', headers=self.auth(self.owner), json={'school_ids': []}).status_code, 400)

    def test_old_send_email_shape_and_blank_email_handling(self):
        good, blank = self.school('Old Good'), self.school('Old Blank', email='')
        with patch.object(service, 'send_emails_over_connection',
                          side_effect=lambda _a, _b, _c, jobs: [(job, True, None) for job in jobs]) as send:
            response = self.client.post('/api/send-email', headers=self.auth(self.owner),
                                        json={'school_ids': [good.id, blank.id]})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(set(data), {'status', 'sent_count', 'batches_processed', 'errors'})
        self.assertEqual((data['status'], data['sent_count'], data['batches_processed']), ('1 emails sent successfully', 1, 1))
        self.assertEqual(len(data['errors']), 1)
        self.assertIn('Old Blank', data['errors'][0])
        self.assertEqual([job['to_email'] for job in send.call_args.args[3]], [good.email])
        self.assertEqual(self.client.post('/api/send-email', headers=self.auth(self.owner), json={'school_ids': []}).status_code, 400)

    def test_send_emails_over_connection_still_reuses_one_connection(self):
        jobs = [{'to_email': f'a{index}@example.test', 'subject': 's', 'body': 'b', 'pdf_files': []} for index in range(3)]
        self.fake.fail_for = {'a1@example.test'}
        with patch.object(service, 'open_smtp_connection', side_effect=lambda *a, **k: self.fake) as opener:
            results = service.send_emails_over_connection('owner@example.test', 'pw', 'Owner', jobs, delay_seconds=0)
        self.assertEqual([item[1] for item in results], [True, False, True])
        self.assertEqual(opener.call_count, 1)
        self.assertTrue(all('message_id' in job for job, ok, _ in results if ok))
        with patch.object(service, 'open_smtp_connection', side_effect=RuntimeError('down')):
            failed = service.send_emails_over_connection('owner@example.test', 'pw', 'Owner', jobs, delay_seconds=0)
        self.assertTrue(all(not ok and error.startswith('SMTP login failed') for _job, ok, error in failed))


if __name__ == '__main__':
    unittest.main()
