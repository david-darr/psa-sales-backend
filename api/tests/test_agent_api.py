"""Agent API keys: hashing, expiry, revocation, scopes, role scoping, limits and audit."""
import base64
import os
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service
from api import agent_api

BASE = '/api/agent/v1'


class AgentApiTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        self.rep = service.User(name='Rep', email='rep@example.test', admin=False, password_hash='unused')
        self.other = service.User(name='Other', email='other@example.test', admin=False, password_hash='unused')
        self.admin = service.User(name='Admin', email='admin@example.test', admin=True, password_hash='unused')
        service.db.session.add_all([self.rep, self.other, self.admin])
        service.db.session.flush()
        self.mine = service.SalesSchool(school_name='Maple School', email='maple@example.test',
                                        school_type='preschool', user_id=self.rep.id, status='contacted')
        self.theirs = service.SalesSchool(school_name='Birch School', email='birch@example.test',
                                          school_type='elementary', user_id=self.other.id, status='pending')
        service.db.session.add_all([self.mine, self.theirs])
        service.db.session.commit()
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def jwt(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def create_key(self, user, scope='read', days=30, name='Kairos'):
        response = self.client.post('/api/agent-keys', headers=self.jwt(user),
                                    json={'name': name, 'scope': scope, 'expires_in_days': days})
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()

    def bearer(self, token):
        return {'Authorization': 'Bearer ' + token}

    def test_key_is_shown_once_and_stored_hashed(self):
        created = self.create_key(self.rep)
        self.assertRegex(created['key'], r'^psak_[0-9a-f]{64}$')
        row = service.AgentApiKey.query.one()
        self.assertEqual(row.key_hash, agent_api.hash_key(created['key']))
        self.assertNotIn(created['key'], (row.key_hash, row.key_hint, row.name))
        listed = self.client.get('/api/agent-keys', headers=self.jwt(self.rep)).get_json()
        self.assertEqual(len(listed['items']), 1)
        self.assertNotIn('key', listed['items'][0])
        self.assertTrue(listed['base_url'].endswith(BASE))
        # Other employees never see someone else's keys.
        self.assertEqual(self.client.get('/api/agent-keys', headers=self.jwt(self.other)).get_json()['items'], [])

    def test_key_creation_validates_inputs_and_cap(self):
        for body in ({'name': 'x', 'scope': 'admin', 'expires_in_days': 30},
                     {'name': 'x', 'scope': 'read', 'expires_in_days': 365},
                     {'name': '', 'scope': 'read', 'expires_in_days': 7},
                     {'name': 'x', 'scope': 'read', 'expires_in_days': 7, 'user_id': self.admin.id}):
            self.assertEqual(self.client.post('/api/agent-keys', headers=self.jwt(self.rep), json=body).status_code, 400)
        for index in range(agent_api.MAX_ACTIVE_KEYS):
            self.create_key(self.rep, name=f'k{index}')
        response = self.client.post('/api/agent-keys', headers=self.jwt(self.rep),
                                    json={'name': 'one more', 'scope': 'read', 'expires_in_days': 7})
        self.assertEqual(response.status_code, 400)

    def test_invalid_expired_and_revoked_keys_are_rejected(self):
        self.assertEqual(self.client.get(BASE + '/me').status_code, 401)
        self.assertEqual(self.client.get(BASE + '/me', headers=self.bearer('psak_' + '0' * 64)).status_code, 401)
        created = self.create_key(self.rep)
        self.assertEqual(self.client.get(BASE + '/me', headers=self.bearer(created['key'])).status_code, 200)
        # A web session token is not an agent key.
        self.assertEqual(self.client.get(BASE + '/me', headers=self.jwt(self.rep)).status_code, 401)
        # Only the owner can revoke.
        self.assertEqual(self.client.delete(f"/api/agent-keys/{created['id']}", headers=self.jwt(self.other)).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/agent-keys/{created['id']}", headers=self.jwt(self.rep)).status_code, 200)
        self.assertEqual(self.client.get(BASE + '/me', headers=self.bearer(created['key'])).status_code, 401)
        expiring = self.create_key(self.rep, days=7)
        row = service.db.session.get(service.AgentApiKey, expiring['id'])
        row.expires_at = service.utc_now() - timedelta(seconds=1)
        service.db.session.commit()
        self.assertEqual(self.client.get(BASE + '/me', headers=self.bearer(expiring['key'])).status_code, 401)

    def test_me_reports_current_role(self):
        created = self.create_key(self.rep, scope='write')
        data = self.client.get(BASE + '/me', headers=self.bearer(created['key'])).get_json()
        self.assertEqual((data['id'], data['role'], data['key']['scope']), (self.rep.id, 'rep', 'write'))
        self.rep.admin = True
        service.db.session.commit()
        data = self.client.get(BASE + '/me', headers=self.bearer(created['key'])).get_json()
        self.assertEqual(data['role'], 'admin')

    def test_rep_key_sees_only_own_records_and_admin_sees_team(self):
        rep_key = self.create_key(self.rep)['key']
        admin_key = self.create_key(self.admin)['key']
        rows = self.client.get(BASE + '/schools', headers=self.bearer(rep_key)).get_json()
        self.assertEqual([row['id'] for row in rows['items']], [self.mine.id])
        self.assertEqual(self.client.get(f'{BASE}/schools/{self.theirs.id}', headers=self.bearer(rep_key)).status_code, 404)
        self.assertEqual(self.client.get(BASE + '/schools', headers=self.bearer(admin_key)).get_json()['total'], 2)
        detail = self.client.get(f'{BASE}/schools/{self.theirs.id}', headers=self.bearer(admin_key)).get_json()
        self.assertEqual(detail['school']['school_name'], 'Birch School')
        for path in ('/team', '/accounts', '/commissions'):
            self.assertEqual(self.client.get(BASE + path, headers=self.bearer(rep_key)).status_code, 403, path)
        self.assertEqual(len(self.client.get(BASE + '/team', headers=self.bearer(admin_key)).get_json()), 3)
        accounts = self.client.get(BASE + '/accounts', headers=self.bearer(admin_key)).get_json()
        self.assertEqual(accounts['scope'], 'all')
        pipeline = self.client.get(BASE + '/pipeline', headers=self.bearer(rep_key)).get_json()
        self.assertEqual(pipeline['schools'], 1)

    def test_read_key_cannot_write(self):
        key = self.create_key(self.rep, scope='read')['key']
        response = self.client.post(BASE + '/tasks', headers=self.bearer(key), json={'title': 'Call'})
        self.assertEqual(response.status_code, 403)
        response = self.client.patch(f'{BASE}/schools/{self.mine.id}', headers=self.bearer(key), json={'status': 'meeting'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(service.SalesTask.query.count(), 0)

    def test_tasks_create_list_and_version_conflicts(self):
        key = self.create_key(self.rep, scope='write')['key']
        created = self.client.post(BASE + '/tasks', headers=self.bearer(key),
                                   json={'title': 'Call the director', 'school_id': self.mine.id,
                                         'due_at': '2026-10-30T15:00:00Z', 'priority': 'high'})
        self.assertEqual(created.status_code, 201, created.get_json())
        task = created.get_json()
        self.assertEqual((task['user_id'], task['version']), (self.rep.id, 1))
        # Reps cannot assign teammates or attach other reps' schools.
        self.assertEqual(self.client.post(BASE + '/tasks', headers=self.bearer(key),
                                          json={'title': 'x', 'user_id': self.other.id}).status_code, 403)
        self.assertEqual(self.client.post(BASE + '/tasks', headers=self.bearer(key),
                                          json={'title': 'x', 'school_id': self.theirs.id}).status_code, 404)
        listed = self.client.get(BASE + '/tasks?view=open', headers=self.bearer(key)).get_json()
        self.assertEqual([row['id'] for row in listed['items']], [task['id']])
        stale = self.client.patch(f"{BASE}/tasks/{task['id']}", headers=self.bearer(key),
                                  json={'version': 7, 'status': 'completed'})
        self.assertEqual(stale.status_code, 409)
        done = self.client.patch(f"{BASE}/tasks/{task['id']}", headers=self.bearer(key),
                                 json={'version': 1, 'status': 'completed'})
        self.assertEqual((done.status_code, done.get_json()['version']), (200, 2))

    def test_school_updates_are_limited_and_assignment_is_admin_only(self):
        rep_key = self.create_key(self.rep, scope='write')['key']
        admin_key = self.create_key(self.admin, scope='write')['key']
        response = self.client.patch(f'{BASE}/schools/{self.mine.id}', headers=self.bearer(rep_key),
                                     json={'status': 'meeting', 'next_action': 'Send pricing',
                                           'next_action_at': '2026-11-02T14:00:00Z'})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['status'], 'meeting')
        self.assertEqual(self.client.patch(f'{BASE}/schools/{self.mine.id}', headers=self.bearer(rep_key),
                                           json={'email': 'new@example.test'}).status_code, 400)
        self.assertEqual(self.client.patch(f'{BASE}/schools/{self.mine.id}', headers=self.bearer(rep_key),
                                           json={'user_id': self.other.id}).status_code, 403)
        self.assertEqual(self.client.patch(f'{BASE}/schools/{self.theirs.id}', headers=self.bearer(rep_key),
                                           json={'status': 'meeting'}).status_code, 404)
        self.assertEqual(self.client.post(BASE + '/schools/assign', headers=self.bearer(rep_key),
                                          json={'ids': [self.mine.id], 'user_id': self.other.id}).status_code, 403)
        response = self.client.post(BASE + '/schools/assign', headers=self.bearer(admin_key),
                                    json={'ids': [self.mine.id], 'user_id': self.other.id})
        self.assertEqual((response.status_code, response.get_json()), (200, {'updated': 1}))
        service.db.session.refresh(self.mine)
        self.assertEqual(self.mine.user_id, self.other.id)
        actors = {row.actor_id for row in service.SchoolActivity.query.all()}
        self.assertEqual(actors, {self.rep.id, self.admin.id})

    def test_activity_logging(self):
        key = self.create_key(self.rep, scope='write')['key']
        response = self.client.post(f'{BASE}/schools/{self.mine.id}/activities', headers=self.bearer(key),
                                    json={'kind': 'call', 'detail': 'Spoke with the director.'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.client.post(f'{BASE}/schools/{self.mine.id}/activities', headers=self.bearer(key),
                                          json={'kind': 'email', 'detail': 'x'}).status_code, 400)
        self.assertEqual(self.client.post(f'{BASE}/schools/{self.theirs.id}/activities', headers=self.bearer(key),
                                          json={'kind': 'note', 'detail': 'x'}).status_code, 404)

    def test_outreach_is_read_only(self):
        key = self.create_key(self.rep, scope='write')['key']
        self.assertEqual(self.client.get(BASE + '/outreach', headers=self.bearer(key)).get_json(), {'items': []})
        self.assertEqual(self.client.post(BASE + '/outreach', headers=self.bearer(key), json={}).status_code, 405)
        self.assertEqual(self.client.get(BASE + '/outreach/999', headers=self.bearer(key)).status_code, 404)

    def test_commissions_degrade_until_feature_exists(self):
        key = self.create_key(self.admin)['key']
        with patch.dict(service.app.view_functions):
            service.app.view_functions.pop('admin_commissions', None)
            response = self.client.get(BASE + '/commissions', headers=self.bearer(key))
        self.assertEqual(response.status_code, 404)
        self.assertFalse(response.get_json()['available'])

    def test_rate_limit_and_content_free_audit(self):
        created = self.create_key(self.rep)
        key = created['key']
        with patch.object(agent_api, 'RATE_LIMIT_PER_MINUTE', 3):
            statuses = [self.client.get(f'{BASE}/schools?q=secret-term', headers=self.bearer(key)).status_code
                        for _ in range(4)]
            limited = self.client.get(BASE + '/me', headers=self.bearer(key))
        self.assertEqual(statuses, [200, 200, 200, 429])
        self.assertEqual(limited.headers.get('Retry-After'), '60')
        rows = service.AgentApiAudit.query.all()
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual((row.key_id, row.user_id), (created['id'], self.rep.id))
            self.assertNotIn('secret', row.route)
            self.assertNotIn(str(self.mine.id), row.route)
        self.assertIsNotNone(service.db.session.get(service.AgentApiKey, created['id']).last_used_at)

    def test_kill_switch(self):
        key = self.create_key(self.rep)['key']
        with patch.dict(os.environ, {'AGENT_API_ENABLED': 'false'}):
            self.assertEqual(self.client.get(BASE + '/me', headers=self.bearer(key)).status_code, 503)


if __name__ == '__main__':
    unittest.main()
