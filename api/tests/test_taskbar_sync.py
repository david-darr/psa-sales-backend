"""Taskbar two-way sync: mapping, signatures, echo suppression, conflicts, retries. No network."""
import base64
import json
import os
import time
import unittest
import uuid
from datetime import datetime, timedelta

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service
from api import taskbar_sync as ts

PROGRAM = 'b2000000-0000-4000-8000-000000000001'
ENV = {
    'TASKBAR_SYNC_ENABLED': 'true', 'TASKBAR_API_URL': 'https://taskbar.example.test/functions/v1/agent-api/v1',
    'TASKBAR_API_KEY': 'tbk_' + 'a' * 64, 'TASKBAR_SYNC_URL': 'https://taskbar.example.test/functions/v1/psa-sync',
    'TASKBAR_WEBHOOK_SECRET': 'test-secret', 'TASKBAR_SALES_PROGRAM_ID': PROGRAM,
}
OWNER_TB, OTHER_TB = str(uuid.uuid4()), str(uuid.uuid4())


def stamp(dt):
    return dt.isoformat() + 'Z'


class FakeTaskbar:
    """In-memory agent API with revision checks, mirroring the 409 contract."""

    def __init__(self):
        self.tasks, self.calls, self.fail_next = {}, [], []
        self.members = []

    def directory(self):
        return self.members

    def call(self, method, path, body=None, params=None):
        self.calls.append((method, path, body))
        if self.fail_next:
            raise self.fail_next.pop(0)
        if method == 'GET' and path == '/tasks':
            q = params['q']
            return {'items': [t for t in self.tasks.values() if q in t['description']]}
        if method == 'POST' and path == '/tasks':
            task = dict(body, id=str(uuid.uuid4()), revision=1, updated_at=stamp(ts.now()))
            task.setdefault('assignee', None)
            self.tasks[task['id']] = task
            return dict(task)
        task_id = path.split('/')[2]
        task = self.tasks.get(task_id)
        if task is None:
            raise ts.TaskbarError(404, 'Task unavailable')
        if method == 'GET':
            return dict(task)
        if body['revision'] != task['revision']:
            raise ts.TaskbarError(409, 'Task changed')
        task.update({k: v for k, v in body.items() if k != 'revision'})
        task['revision'] += 1
        task['updated_at'] = stamp(ts.now())
        return dict(task)

    def remote_edit(self, task_id, **fields):
        task = self.tasks[task_id]
        task.update(fields)
        task['revision'] += 1
        task['updated_at'] = stamp(ts.now() + timedelta(seconds=1))
        return dict(task)


class MappingTests(unittest.TestCase):
    def test_status_and_priority_round_trip(self):
        self.assertEqual(ts.to_taskbar_status('completed'), 'Completed')
        self.assertEqual(ts.to_taskbar_status('open'), 'Not Started')
        self.assertEqual(ts.to_taskbar_status('open', 'In Progress'), 'In Progress')
        self.assertEqual(ts.to_taskbar_status('open', 'Completed'), 'Not Started')
        for remote, psa in (('Not Started', 'open'), ('In Progress', 'open'), ('Completed', 'completed')):
            self.assertEqual(ts.to_psa_status(remote), psa)
        self.assertEqual(ts.to_taskbar_priority('high'), 'High')
        self.assertEqual(ts.to_taskbar_priority('normal'), 'Medium')
        self.assertEqual(ts.to_taskbar_priority('normal', 'Low'), 'Low')
        self.assertEqual(ts.to_taskbar_priority('normal', 'High'), 'Medium')
        self.assertEqual([ts.to_psa_priority(p) for p in ('High', 'Medium', 'Low')], ['high', 'normal', 'normal'])

    def test_title_fits_taskbar_limit(self):
        self.assertEqual(ts.taskbar_title('  Call  '), 'Call')
        long = 'x' * 200
        self.assertEqual(len(ts.taskbar_title(long)), 140)
        self.assertTrue(ts.taskbar_title(long).endswith('...'))

    def test_remote_times_become_naive_utc(self):
        self.assertEqual(ts.parse_remote_time('2026-10-29T09:00:00-04:00'), datetime(2026, 10, 29, 13, 0))
        self.assertEqual(ts.iso_z(datetime(2026, 10, 29, 13, 0, 5, 9)), '2026-10-29T13:00:05Z')

    def test_signature_checks(self):
        body = b'{"a":1}'
        now = int(time.time())
        good = ts.sign('s', now, body)
        self.assertTrue(ts.verify_signature('s', str(now), good, body))
        self.assertFalse(ts.verify_signature('s', str(now), good, b'{"a":2}'))
        self.assertFalse(ts.verify_signature('other', str(now), good, body))
        self.assertFalse(ts.verify_signature('s', str(now - 600), ts.sign('s', now - 600, body), body))
        self.assertFalse(ts.verify_signature('s', 'nope', good, body))
        self.assertFalse(ts.verify_signature('', str(now), good, body))

    def test_signature_matches_taskbar_function(self):
        # Same vector as Taskbar's scripts/psa-sync.test.mjs.
        self.assertEqual(ts.sign('test-secret', 1761700000, b'{"event":"task.upsert"}'),
                         'v1=a01bdbe7093f2dc4fe1b15f5a573a69856aa3a2661a6ad53dbb81b71f561e45b')

    def test_config_requires_every_value(self):
        self.assertTrue(ts.SyncConfig(ENV).enabled)
        self.assertFalse(ts.SyncConfig(dict(ENV, TASKBAR_SYNC_ENABLED='false')).enabled)
        self.assertFalse(ts.SyncConfig(dict(ENV, TASKBAR_API_URL='http://insecure.test')).enabled)
        self.assertFalse(ts.SyncConfig(dict(ENV, TASKBAR_WEBHOOK_SECRET='')).enabled)


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        self.sync = service.app.extensions['taskbar_sync']
        self.saved = (self.sync.config, self.sync.client)
        self.fake = FakeTaskbar()
        self.sync.config, self.sync.client = ts.SyncConfig(ENV), self.fake
        self.sync.directory_at = 0
        self.owner = service.User(name='Owner', email='Owner@Example.test', admin=False, password_hash='x')
        self.other = service.User(name='Other', email='other@example.test', admin=False, password_hash='x')
        self.admin = service.User(name='Admin', email='admin@example.test', admin=True, password_hash='x')
        service.db.session.add_all([self.owner, self.other, self.admin])
        service.db.session.flush()
        self.school = service.SalesSchool(school_name='Maple School', email='maple@example.test', school_type='preschool',
                                          user_id=self.owner.id, status='contacted')
        service.db.session.add(self.school)
        service.db.session.commit()
        self.fake.members = [{'user_id': OWNER_TB, 'email': 'owner@example.test'},
                             {'user_id': OTHER_TB, 'email': 'OTHER@example.test'}]
        self.client = service.app.test_client()
        self.Link = service.db.Model.registry._class_registry['SalesTaskLink']

    def tearDown(self):
        self.sync.config, self.sync.client = self.saved
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def make_task(self, **fields):
        values = dict(title='Call the director', user_id=self.owner.id, school_id=self.school.id,
                      due_at=datetime(2026, 11, 2, 15, 0))
        values.update(fields)
        task = service.SalesTask(**values)
        service.db.session.add(task)
        service.db.session.commit()
        return task

    def link(self, task):
        return service.db.session.get(self.Link, task.id)

    def post_event(self, payload, secret='test-secret', when=None):
        body = json.dumps(payload).encode()
        moment = int(when or time.time())
        return self.client.post('/api/integrations/taskbar/webhook', data=body, headers={
            'Content-Type': 'application/json', 'X-PSA-Sync-Timestamp': str(moment),
            'X-PSA-Sync-Signature': ts.sign(secret, moment, body)})

    def event(self, remote, kind='task.upsert', email=None):
        return {'event': kind, 'task': remote, 'assignee_email': email}

    # -- PSA to Taskbar -----------------------------------------------------------
    def test_create_pushes_mapped_task_once(self):
        task = self.make_task(priority='high')
        self.assertEqual(self.sync.run_once(), {'created': 1})
        link = self.link(task)
        remote = self.fake.tasks[link.taskbar_task_id]
        self.assertEqual(remote['assignee'], OWNER_TB)
        self.assertEqual(remote['program_id'], PROGRAM)
        self.assertEqual((remote['priority'], remote['status'], remote['due_at']), ('High', 'Not Started', '2026-11-02T15:00:00Z'))
        self.assertIn(ts.marker(task.id), remote['description'])
        self.assertIn('Maple School', remote['description'])
        self.assertEqual((link.state, link.psa_version, link.taskbar_revision), ('synced', 1, 1))
        self.assertEqual(self.sync.run_once(), {})

    def test_completion_and_reassignment_push_updates(self):
        task = self.make_task()
        self.sync.run_once()
        response = self.client.patch(f'/api/crm/tasks/{task.id}', headers=self.auth(self.owner),
                                     json={'version': 1, 'status': 'completed'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sync.run_once(), {'updated': 1})
        remote = self.fake.tasks[self.link(task).taskbar_task_id]
        self.assertEqual(remote['status'], 'Completed')
        # Bulk reassignment bypasses ORM events; the timed pass still catches it.
        other_task = self.make_task(title='Send pricing')
        self.sync.run_once()
        self.client.post('/api/crm/schools/bulk', headers=self.auth(self.admin),
                         json={'ids': [self.school.id], 'user_id': self.other.id})
        self.assertEqual(self.sync.run_once(), {'updated': 1})
        self.assertEqual(self.fake.tasks[self.link(other_task).taskbar_task_id]['assignee'], OTHER_TB)

    def test_unmapped_owner_waits_and_completed_history_is_not_backfilled(self):
        self.fake.members = []
        task = self.make_task()
        self.make_task(status='completed', completed_at=ts.now())
        self.assertEqual(self.sync.run_once(), {'unmapped': 1})
        self.assertEqual(self.fake.tasks, {})
        self.assertIsNotNone(self.link(task).next_attempt_at)

    def test_lost_create_response_adopts_existing_copy(self):
        task = self.make_task()
        real_call = self.fake.call

        def lose_response(method, path, body=None, params=None):
            result = real_call(method, path, body, params)
            if method == 'POST':
                raise ts.TaskbarError(0, 'Timeout')
            return result
        self.fake.call = lose_response
        self.assertEqual(self.sync.run_once(), {'error': 1})
        self.fake.call = real_call
        self.link(task).next_attempt_at = None
        service.db.session.commit()
        self.assertEqual(self.sync.run_once(), {'updated': 1})
        self.assertEqual(len(self.fake.tasks), 1)

    def test_failures_back_off_and_rate_limit_stops_batch(self):
        first, second = self.make_task(), self.make_task(title='Second')
        self.fake.fail_next = [ts.TaskbarError(429, 'Rate limit')]
        self.assertEqual(self.sync.run_once(), {'rate_limited': 1})
        link = self.link(first)
        self.assertEqual((link.state, link.attempts), ('error', 1))
        self.assertGreater(link.next_attempt_at, ts.now() + timedelta(seconds=50))
        self.assertEqual(self.sync.run_once(), {'created': 1})
        self.assertEqual(self.link(second).state, 'synced')

    def test_missing_remote_task_detaches_without_recreating(self):
        task = self.make_task()
        self.sync.run_once()
        self.fake.tasks.clear()
        task.title = 'Renamed'
        task.version += 1
        service.db.session.commit()
        self.assertEqual(self.sync.run_once(), {'error': 1})
        self.assertEqual(self.link(task).state, 'detached')
        self.link(task).next_attempt_at = None
        service.db.session.commit()
        self.assertEqual(self.sync.run_once(), {})
        self.assertEqual(self.fake.tasks, {})

    def test_disabled_sync_does_nothing(self):
        self.sync.config = ts.SyncConfig({})
        self.make_task()
        self.assertEqual(self.sync.run_once(), {'skipped': 'disabled'})
        self.assertEqual(self.post_event({}).status_code, 503)

    # -- Taskbar to PSA -----------------------------------------------------------
    def test_webhook_rejects_bad_signatures(self):
        self.assertEqual(self.post_event({'task': {}}, secret='wrong').status_code, 401)
        self.assertEqual(self.post_event({'task': {}}, when=time.time() - 900).status_code, 401)
        response = self.client.post('/api/integrations/taskbar/webhook', data=b'{}', headers={'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 401)

    def test_echo_of_our_write_is_ignored(self):
        task = self.make_task()
        self.sync.run_once()
        remote = self.fake.tasks[self.link(task).taskbar_task_id]
        response = self.post_event(self.event(remote))
        self.assertEqual(response.get_json(), {'result': 'ignored_echo'})
        service.db.session.refresh(task)
        self.assertEqual(task.version, 1)

    def test_create_echo_before_response_is_matched_by_marker(self):
        task = self.make_task()
        # The worker inserts the link row before its POST; an echo can arrive before the response is stored.
        service.db.session.add(self.Link(sales_task_id=task.id, psa_version=0))
        service.db.session.commit()
        remote = {'id': str(uuid.uuid4()), 'title': 'Call the director', 'program_id': PROGRAM, 'revision': 1,
                  'description': 'Synced from PSA Sales ' + ts.marker(task.id), 'status': 'Not Started',
                  'priority': 'Medium', 'due_at': '2026-11-02T15:00:00Z', 'assignee': OWNER_TB,
                  'updated_at': stamp(ts.now())}
        self.sync.refresh_directory()
        self.assertEqual(self.post_event(self.event(remote)).status_code, 200)
        self.assertEqual(service.SalesTask.query.count(), 1)
        self.assertEqual(self.link(task).taskbar_task_id, remote['id'])

    def test_remote_edit_applies_and_does_not_bounce_back(self):
        task = self.make_task()
        self.sync.run_once()
        tb_id = self.link(task).taskbar_task_id
        remote = self.fake.remote_edit(tb_id, title='Call the new director', status='In Progress', priority='High',
                                       due_at='2026-11-05T14:00:00Z')
        self.assertEqual(self.post_event(self.event(remote)).get_json(), {'result': 'applied'})
        service.db.session.refresh(task)
        self.assertEqual((task.title, task.status, task.priority, task.due_at, task.version),
                         ('Call the new director', 'open', 'high', datetime(2026, 11, 5, 14, 0), 2))
        calls = len(self.fake.calls)
        self.assertEqual(self.sync.run_once(), {})
        self.assertEqual(len(self.fake.calls), calls)
        # "In Progress" survives a later PSA edit instead of being reset to "Not Started".
        task.due_at = datetime(2026, 11, 6, 14, 0)
        task.version += 1
        service.db.session.commit()
        self.sync.run_once()
        self.assertEqual(self.fake.tasks[tb_id]['status'], 'In Progress')

    def test_remote_completion_sets_completed_at_and_replay_is_harmless(self):
        task = self.make_task()
        self.sync.run_once()
        remote = self.fake.remote_edit(self.link(task).taskbar_task_id, status='Completed')
        self.post_event(self.event(remote))
        self.assertEqual(self.post_event(self.event(remote)).get_json(), {'result': 'ignored_echo'})
        service.db.session.refresh(task)
        self.assertEqual(task.status, 'completed')
        self.assertIsNotNone(task.completed_at)
        self.assertEqual(task.version, 2)

    def test_truncated_title_does_not_overwrite_full_psa_title(self):
        title = 'Follow up ' + 'z' * 200
        task = self.make_task(title=title)
        self.sync.run_once()
        remote = self.fake.remote_edit(self.link(task).taskbar_task_id, priority='High')
        self.post_event(self.event(remote))
        service.db.session.refresh(task)
        self.assertEqual((task.title, task.priority), (title, 'high'))

    def test_undated_task_keeps_no_due_date(self):
        task = self.make_task(due_at=None)
        self.sync.run_once()
        remote = self.fake.tasks[self.link(task).taskbar_task_id]
        self.assertEqual(remote['due_at'], ts.iso_z(ts.default_due(task)))
        self.post_event(self.event(self.fake.remote_edit(remote['id'], priority='High')))
        service.db.session.refresh(task)
        self.assertIsNone(task.due_at)

    def test_conflict_newer_psa_edit_wins(self):
        task = self.make_task()
        self.sync.run_once()
        tb_id = self.link(task).taskbar_task_id
        stale = self.fake.remote_edit(tb_id, title='Older Taskbar title')
        stale['updated_at'] = stamp(ts.now() - timedelta(minutes=5))
        self.fake.tasks[tb_id]['updated_at'] = stale['updated_at']
        task.title, task.version = 'Newer PSA title', task.version + 1
        link = self.link(task)
        link.dirty_at = ts.now()
        service.db.session.commit()
        self.assertEqual(self.post_event(self.event(stale)).get_json(), {'result': 'conflict_local_won'})
        self.assertEqual(self.sync.run_once(), {'updated': 1})
        self.assertEqual(self.fake.tasks[tb_id]['title'], 'Newer PSA title')
        service.db.session.refresh(task)
        self.assertEqual(task.title, 'Newer PSA title')

    def test_conflict_newer_taskbar_edit_wins_on_409(self):
        task = self.make_task()
        self.sync.run_once()
        tb_id = self.link(task).taskbar_task_id
        task.title, task.version = 'PSA title', task.version + 1
        link = self.link(task)
        link.dirty_at = ts.now() - timedelta(minutes=5)
        service.db.session.commit()
        self.fake.remote_edit(tb_id, title='Taskbar title')  # webhook not delivered yet
        self.assertEqual(self.sync.run_once(), {'conflict_remote_won': 1})
        service.db.session.refresh(task)
        self.assertEqual(task.title, 'Taskbar title')
        self.assertEqual(self.sync.run_once(), {})

    def test_taskbar_created_task_lands_for_mapped_owner(self):
        self.sync.refresh_directory()
        remote = {'id': str(uuid.uuid4()), 'title': 'Drop off brochures', 'program_id': PROGRAM, 'revision': 1,
                  'description': '', 'status': 'Not Started', 'priority': 'Low', 'due_at': '2026-11-03T16:00:00Z',
                  'assignee': OTHER_TB, 'updated_at': stamp(ts.now())}
        response = self.post_event(self.event(remote))
        self.assertEqual(response.status_code, 201)
        task = service.db.session.get(service.SalesTask, response.get_json()['sales_task_id'])
        self.assertEqual((task.user_id, task.priority, task.school_id), (self.other.id, 'normal', None))
        self.assertEqual(self.sync.run_once(), {})
        unassigned = dict(remote, id=str(uuid.uuid4()), assignee=None)
        self.assertEqual(self.post_event(self.event(unassigned)).get_json(), {'result': 'ignored_unmapped'})

    def test_new_member_maps_by_email_on_first_event(self):
        newcomer = str(uuid.uuid4())
        remote = {'id': str(uuid.uuid4()), 'title': 'Intro call', 'program_id': PROGRAM, 'revision': 1, 'description': '',
                  'status': 'Not Started', 'priority': 'Medium', 'due_at': '2026-11-03T16:00:00Z', 'assignee': newcomer,
                  'updated_at': stamp(ts.now())}
        self.assertEqual(self.post_event(self.event(remote, email='ADMIN@example.test')).status_code, 201)
        self.assertEqual(self.sync.psa_user(newcomer), self.admin.id)

    def test_reassignment_against_school_owner_is_reverted(self):
        task = self.make_task()
        self.sync.run_once()
        tb_id = self.link(task).taskbar_task_id
        self.post_event(self.event(self.fake.remote_edit(tb_id, assignee=OTHER_TB)))
        service.db.session.refresh(task)
        self.assertEqual(task.user_id, self.owner.id)
        self.assertEqual(self.sync.run_once(), {'updated': 1})
        self.assertEqual(self.fake.tasks[tb_id]['assignee'], OWNER_TB)

    def test_moved_out_of_sales_program_detaches(self):
        task = self.make_task()
        self.sync.run_once()
        tb_id = self.link(task).taskbar_task_id
        moved = self.fake.remote_edit(tb_id, program_id=str(uuid.uuid4()))
        self.assertEqual(self.post_event(self.event(moved)).get_json(), {'result': 'detached'})
        task.title, task.version = 'Edited later', task.version + 1
        service.db.session.commit()
        self.assertEqual(self.sync.run_once(), {})
        deleted = self.post_event(self.event({'id': str(uuid.uuid4()), 'program_id': PROGRAM}, kind='task.deleted'))
        self.assertEqual(deleted.get_json(), {'result': 'ignored'})

    def test_directory_matches_by_email_and_drops_departed(self):
        self.assertEqual(self.sync.refresh_directory(), 2)
        self.assertEqual(self.sync.psa_user(OTHER_TB.upper()), self.other.id)
        self.fake.members = self.fake.members[:1]
        self.assertEqual(self.sync.refresh_directory(), 1)
        self.assertIsNone(self.sync.psa_user(OTHER_TB))

    def test_status_endpoint_is_admin_only(self):
        self.make_task()
        self.sync.run_once()
        self.assertEqual(self.client.get('/api/integrations/taskbar/status', headers=self.auth(self.owner)).status_code, 403)
        data = self.client.get('/api/integrations/taskbar/status', headers=self.auth(self.admin)).get_json()
        self.assertEqual((data['enabled'], data['links'], data['mapped_users']), (True, {'synced': 1}, 2))
        self.assertNotIn('api_key', json.dumps(data))


if __name__ == '__main__':
    unittest.main()
