"""Retired commission routes, join links and login hardening."""
import base64
import os
import unittest
from datetime import datetime, timedelta, timezone

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service  # noqa: E402


class AdminSalesBase(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        User = service.User
        self.admin = User(name='Ricky Boss', email='ricky@example.test', admin=True, password_hash='x')
        self.john = User(name='John Smith', email='john@example.test', admin=False, password_hash='x',
                         commission_rate=10)
        self.mary = User(name='Mary Jones', email='mary@example.test', admin=False, password_hash='x',
                         commission_rate=8)
        service.db.session.add_all([self.admin, self.john, self.mary])
        service.db.session.flush()
        self.open_school = self.school('Alpha Prep', self.john, 'meeting')
        self.won = self.school('Beta Academy', self.john, 'partner',
                               closed_at=datetime(2026, 10, 1, 15, tzinfo=timezone.utc), closed_by_id=self.john.id)
        service.db.session.commit()
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def school(self, name, owner, status, **extra):
        school = service.SalesSchool(school_name=name, email=name.split()[0].lower() + '@example.test',
                                     school_type='preschool', user_id=owner.id, status=status, **extra)
        service.db.session.add(school)
        return school

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}


class RetiredCommissionTests(AdminSalesBase):
    def test_legacy_commission_routes_are_removed(self):
        for method, url in [('get', '/api/admin/commissions'),
                            ('patch', f'/api/admin/reps/{self.john.id}'),
                            ('put', f'/api/admin/schools/{self.won.id}/close')]:
            response = getattr(self.client, method)(url, json={}, headers=self.auth(self.admin))
            self.assertEqual(response.status_code, 404, url)


class JoinLinkTests(AdminSalesBase):
    def register(self, token, email='new.rep@example.test', password='longenough1'):
        return self.client.post('/api/register', json={
            'name': 'New Rep', 'email': email, 'password': password, 'join_token': token})

    def test_shared_link_signs_up_many_reps_until_limit(self):
        created = self.client.post('/api/join-links', json={'days': 7, 'max_uses': 2, 'label': 'Fall team'},
                                   headers=self.auth(self.admin)).get_json()
        token = created['token']
        self.assertTrue(self.client.post('/api/join-links/check', json={'token': token}).get_json()['valid'])
        self.assertEqual(self.register(token, 'a@example.test').status_code, 200)
        self.assertEqual(self.register(token, 'b@example.test').status_code, 200)
        self.assertEqual(self.register(token, 'c@example.test').status_code, 403)
        listed = self.client.get('/api/join-links', headers=self.auth(self.admin)).get_json()
        self.assertEqual(listed[0]['state'], 'used up')
        self.assertNotIn('token', listed[0])
        new_user = service.User.query.filter_by(email='a@example.test').one()
        self.assertFalse(new_user.admin)

    def test_revoked_expired_and_weak_signups_rejected(self):
        token = self.client.post('/api/join-links', json={}, headers=self.auth(self.admin)).get_json()['token']
        self.assertEqual(self.register(token, password='short').status_code, 400)
        self.assertEqual(self.register(token, email='JOHN@example.test').status_code, 400)
        link = service.JoinLink.query.one()
        link.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        service.db.session.commit()
        self.assertEqual(self.register(token).status_code, 403)
        link.expires_at += timedelta(days=2)
        service.db.session.commit()
        self.client.delete(f'/api/join-links/{link.id}', headers=self.auth(self.admin))
        self.assertEqual(self.register(token).status_code, 403)
        self.assertFalse(self.client.post('/api/join-links/check', json={'token': token}).get_json()['valid'])
        self.assertEqual(self.register('not-a-real-token').status_code, 403)

    def test_login_is_case_insensitive_and_rejects_bad_bodies(self):
        token = self.client.post('/api/join-links', json={}, headers=self.auth(self.admin)).get_json()['token']
        self.register(token, 'Casey@Example.test')
        ok = self.client.post('/api/login', json={'email': ' CASEY@example.TEST ', 'password': 'longenough1'})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.client.post('/api/login', data='nope').status_code, 400)
        self.assertEqual(self.client.post('/api/login', json={'email': 'casey@example.test',
                                                               'password': 'wrong-pass'}).status_code, 401)


if __name__ == '__main__':
    unittest.main()
