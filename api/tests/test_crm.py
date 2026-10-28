"""CRM permissions, bounded queries, task concurrency, and outreach review."""
import base64
import os
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service


class CRMTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        self.owner = service.User(name='Owner', email='owner@example.test', admin=False, password_hash='unused')
        self.other = service.User(name='Other', email='other@example.test', admin=False, password_hash='unused')
        self.admin = service.User(name='Admin', email='admin@example.test', admin=True, password_hash='unused')
        for user in (self.owner, self.other, self.admin):
            user.email_password = service.encrypt_password('dummy-app-password')
        service.db.session.add_all([self.owner, self.other, self.admin])
        service.db.session.flush()
        self.a = service.SalesSchool(school_name='Maple School', email='maple@example.test', school_type='preschool', user_id=self.owner.id, status='contacted')
        self.b = service.SalesSchool(school_name='Birch School', email='birch@example.test', school_type='elementary', user_id=self.other.id, status='pending')
        self.c = service.SalesSchool(school_name='Maple 100% School', email='hundred@example.test', school_type='private', user_id=self.owner.id, status='meeting')
        service.db.session.add_all([self.a, self.b, self.c])
        service.db.session.commit()
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def task(self, school=None):
        task = service.SalesTask(title='Call the director', user_id=self.owner.id,
            school_id=school.id if school else None, due_at=service.utc_now() - timedelta(days=2))
        service.db.session.add(task)
        service.db.session.commit()
        return task

    def test_school_pages_and_literal_search_respect_owner(self):
        path = '/api/crm/schools?limit=1&scope=team'
        data = self.client.get(path, headers=self.auth(self.owner)).get_json()
        self.assertEqual(data['total'], 2)
        self.assertEqual(len(data['items']), 1)
        result = self.client.get('/api/crm/schools?q=100%25', headers=self.auth(self.owner)).get_json()
        self.assertEqual([row['id'] for row in result['items']], [self.c.id])
        self.assertEqual(self.client.get('/api/crm/schools?limit=10000', headers=self.auth(self.owner)).status_code, 400)
        self.assertEqual(self.client.get('/api/crm/schools', headers=self.auth(self.admin)).get_json()['total'], 3)

    def test_bulk_operation_is_atomic_and_admin_only_for_reassignment(self):
        response = self.client.post('/api/crm/schools/bulk', headers=self.auth(self.owner),
            json={'ids': [self.a.id, self.b.id], 'status': 'partner'})
        self.assertEqual(response.status_code, 404)
        service.db.session.refresh(self.a)
        self.assertEqual(self.a.status, 'contacted')
        response = self.client.post('/api/crm/schools/bulk', headers=self.auth(self.owner),
            json={'ids': [self.a.id], 'user_id': self.other.id})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(service.SchoolActivity.query.count(), 0)

    def test_reassignment_transfers_open_tasks_and_logs_actor(self):
        task = self.task(self.a)
        result = self.client.post('/api/crm/schools/bulk', headers=self.auth(self.admin),
            json={'ids': [self.a.id], 'user_id': self.other.id, 'status': 'meeting'})
        self.assertEqual(result.status_code, 200)
        service.db.session.refresh(task)
        self.assertEqual(task.user_id, self.other.id)
        self.assertEqual(task.version, 2)
        self.assertEqual(service.SchoolActivity.query.one().actor_id, self.admin.id)
        data = self.client.get('/api/crm/tasks', headers=self.auth(self.owner)).get_json()
        self.assertEqual(data['total'], 0)

    def test_task_completion_rejects_a_stale_update(self):
        task = self.task()
        path = f'/api/crm/tasks/{task.id}'
        self.assertEqual(self.client.patch(path, headers=self.auth(self.other), json={'status': 'completed', 'version': 1}).status_code, 404)
        result = self.client.patch(path, headers=self.auth(self.owner), json={'status': 'completed', 'version': 1})
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.get_json()['completed_at'])
        self.assertEqual(self.client.patch(path, headers=self.auth(self.owner), json={'status': 'open', 'version': 1}).status_code, 409)
        self.assertEqual(self.client.get('/api/crm/tasks?view=completed', headers=self.auth(self.owner)).get_json()['total'], 1)

    def test_profile_edit_cannot_change_privileges_or_mailbox(self):
        response = self.client.patch('/api/crm/profile', headers=self.auth(self.owner), json={'name': 'Updated Owner', 'phone': '555-0100'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['name'], 'Updated Owner')
        self.assertEqual(self.client.patch('/api/crm/profile', headers=self.auth(self.owner), json={'admin': True}).status_code, 400)
        self.assertEqual(self.client.patch('/api/crm/profile', headers=self.auth(self.owner), json={'email': 'other@example.test'}).status_code, 400)

    def test_task_creation_and_school_assignment_constraints(self):
        result = self.client.post('/api/crm/tasks', headers=self.auth(self.owner),
            json={'title': 'Call', 'school_id': self.b.id})
        self.assertEqual(result.status_code, 404)
        result = self.client.post('/api/crm/tasks', headers=self.auth(self.admin),
            json={'title': 'Call', 'school_id': self.a.id, 'user_id': self.other.id})
        self.assertEqual(result.status_code, 400)
        result = self.client.post('/api/crm/tasks', headers=self.auth(self.admin),
            json={'title': 'Call', 'school_id': self.a.id, 'user_id': self.owner.id, 'due_at': '2026-11-03T00:00:00Z'})
        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.get_json()['owner_name'], 'Owner')

    def test_task_due_views_use_viewers_calendar_day(self):
        task = self.task()
        task.due_at = service.datetime(2026, 10, 28)
        service.db.session.commit()
        with patch('api.crm.now', return_value=service.datetime(2026, 10, 29, 1)):
            result = self.client.get('/api/crm/tasks?view=today&today=2026-10-28', headers=self.auth(self.owner))
        self.assertEqual(result.get_json()['total'], 1)

    def test_overview_and_team_counts_do_not_multiply_joined_rows(self):
        self.task()
        service.db.session.add_all([
            service.SentEmail(school_name='Maple School', school_email=self.a.email, user_id=self.owner.id, responded=True),
            service.SentEmail(school_name='Maple School', school_email=self.a.email, user_id=self.owner.id, responded=False),
            service.SentEmail(school_name='Birch School', school_email=self.b.email, user_id=self.other.id, responded=False),
        ])
        service.db.session.commit()
        data = self.client.get('/api/crm/overview?scope=team', headers=self.auth(self.owner)).get_json()
        self.assertEqual(data['schools'], 2)
        self.assertEqual(data['sent'], 2)
        self.assertEqual(data['response_rate'], 50)
        self.assertEqual(data['tasks_overdue'], 1)
        self.assertEqual(sum(day['sent'] for day in data['trend']), 2)
        team = self.client.get('/api/crm/team', headers=self.auth(self.admin)).get_json()
        row = next(row for row in team if row['id'] == self.owner.id)
        self.assertEqual((row['schools'], row['sent'], row['responses'], row['overdue']), (2, 2, 1, 1))

    def test_directory_hints_do_not_expose_another_owners_workspace(self):
        self.b.set_additional_emails(['office@birch.example.test'])
        service.db.session.add(service.School(name='Birch School', email='office@birch.example.test', address='123 Lane', contact='Director', phone='555'))
        service.db.session.commit()
        response = self.client.get('/api/crm/directory', headers=self.auth(self.owner))
        self.assertEqual(response.status_code, 200)
        row = response.get_json()['items'][0]
        self.assertTrue(row['assigned'])
        self.assertEqual(row['owner_name'], 'Other')
        self.assertIsNone(row['sales_school_id'])

    def test_outreach_review_matches_send_and_prevents_cross_owner_sends(self):
        self.a.school_name = "Maple & Oak's Academy"
        service.db.session.commit()
        selected = {'school_ids': [self.a.id], 'send_to_all_emails': False}
        preview = self.client.post('/api/email-preview', headers=self.auth(self.owner), json=selected)
        self.assertEqual(preview.status_code, 200)
        self.assertIn("Maple & Oak's Academy", preview.get_json()['items'][0]['body'])
        with patch.object(service, 'send_emails_over_connection', side_effect=lambda _a, _b, _c, jobs: [(job, False, 'simulated failure') for job in jobs]) as send:
            self.client.post('/api/send-email', headers=self.auth(self.owner), json=selected)
        self.assertEqual(preview.get_json()['items'][0]['body'], send.call_args.args[3][0]['body'])
        with patch.object(service, 'send_emails_over_connection', side_effect=lambda _a, _b, _c, jobs: [(job, False, 'simulated failure') for job in jobs]) as reviewed_send:
            result = self.client.post('/api/crm/outreach/send', headers=self.auth(self.owner),
                json={**selected, 'preview_token': preview.get_json()['preview_token']})
            self.assertEqual(result.status_code, 200)
            reviewed_send.assert_called_once()
        self.assertEqual(self.client.post('/api/email-preview', headers=self.auth(self.admin), json=selected).status_code, 403)
        self.assertEqual(self.client.post('/api/send-email', headers=self.auth(self.admin), json=selected).status_code, 403)

    def test_new_send_flow_rejects_stale_or_missing_review_without_smtp(self):
        selected = {'school_ids': [self.a.id], 'send_to_all_emails': False}
        preview = self.client.post('/api/email-preview', headers=self.auth(self.owner), json=selected).get_json()
        self.a.contact_name = 'A newly assigned contact'
        service.db.session.commit()
        with patch.object(service, 'send_emails_over_connection') as send:
            stale = self.client.post('/api/crm/outreach/send', headers=self.auth(self.owner),
                json={**selected, 'preview_token': preview['preview_token']})
            self.assertEqual(stale.status_code, 409)
            self.assertEqual(self.client.post('/api/crm/outreach/send', headers=self.auth(self.owner), json=selected).status_code, 409)
            send.assert_not_called()

    def test_scheduled_mail_sync_is_fair_and_continues_backlogs(self):
        from api.mail_jobs import sync_mailboxes
        service.db.session.add_all([
            service.SentEmail(school_name='Maple', school_email=self.a.email, user_id=self.owner.id),
            service.SentEmail(school_name='Birch', school_email=self.b.email, user_id=self.other.id),
            service.MailSyncState(user_id=self.owner.id, last_checked_at=service.utc_now()),
        ])
        service.db.session.commit()
        order = []
        def check(user):
            order.append(user.id)
            return {'replies_found': 0, 'pending_count': 1 if user.id == self.other.id and order.count(user.id) == 1 else 0}
        with patch.object(service, 'sync_user_mailbox', side_effect=check):
            result = sync_mailboxes(service)
        self.assertEqual(order, [self.other.id, self.owner.id, self.other.id])
        self.assertEqual(result['batches'], 3)
        self.assertEqual(result['unfinished'], 0)


if __name__ == '__main__':
    unittest.main()
