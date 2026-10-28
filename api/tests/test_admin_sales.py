"""Commissions, administrator closes, join links and login hardening."""
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


class CommissionTests(AdminSalesBase):
    def test_reps_cannot_see_or_change_commissions(self):
        for method, url, body in (
                ('get', '/api/admin/commissions', None),
                ('patch', f'/api/admin/reps/{self.john.id}', {'commission_rate': 50}),
                ('put', f'/api/admin/schools/{self.open_school.id}/close', {'deal_value': 1000}),
                ('get', '/api/join-links', None)):
            response = getattr(self.client, method)(url, json=body, headers=self.auth(self.john))
            self.assertEqual(response.status_code, 403, url)

    def test_close_without_value_needs_review_and_defaults_to_closer(self):
        data = self.client.get('/api/admin/commissions', headers=self.auth(self.admin)).get_json()
        self.assertEqual(data['summary']['closes'], 1)
        self.assertEqual(data['summary']['needs_review'], 1)
        close = data['closes'][0]
        self.assertEqual(close['earners'][0]['user_id'], self.john.id)
        self.assertEqual(close['earners'][0]['share_pct'], 100)
        self.assertIsNone(close['earners'][0]['commission'])

    def test_admin_close_with_split_and_override(self):
        response = self.client.put(
            f'/api/admin/schools/{self.open_school.id}/close', headers=self.auth(self.admin),
            json={'deal_value': 12000, 'closed_by_id': self.john.id, 'closed_on': '2026-10-20',
                  'splits': [{'user_id': self.john.id, 'share_pct': 60},
                             {'user_id': self.mary.id, 'share_pct': 40, 'rate_pct': 5}]})
        self.assertEqual(response.status_code, 200, response.get_json())
        close = response.get_json()
        self.assertEqual(close['status'], 'partner')
        self.assertTrue(close['closed_at'].startswith('2026-10-20'))
        by_rep = {line['user_id']: line for line in close['earners']}
        self.assertEqual(by_rep[self.john.id]['commission'], 720.0)   # 12000 * 60% * 10%
        self.assertEqual(by_rep[self.mary.id]['commission'], 240.0)   # 12000 * 40% * 5% override
        self.assertFalse(close['needs_review'])

        report = self.client.get('/api/admin/commissions?from=2026-10-15&to=2026-10-31',
                                 headers=self.auth(self.admin)).get_json()
        self.assertEqual(report['summary']['closes'], 1)
        self.assertEqual(report['summary']['commission'], 960.0)
        reps = {rep['id']: rep for rep in report['reps']}
        self.assertEqual(reps[self.mary.id]['credited_value'], 4800.0)

        csv = self.client.get('/api/admin/commissions?format=csv', headers=self.auth(self.admin))
        self.assertEqual(csv.mimetype, 'text/csv')
        self.assertIn('Alpha Prep', csv.get_data(as_text=True))

        # Closing again replaces the split instead of stacking it.
        again = self.client.put(f'/api/admin/schools/{self.open_school.id}/close', headers=self.auth(self.admin),
                                json={'deal_value': 12000}).get_json()
        self.assertEqual(len(again['earners']), 1)
        self.assertEqual(again['earners'][0]['commission'], 1200.0)

    def test_close_validation(self):
        url = f'/api/admin/schools/{self.open_school.id}/close'
        for body in ({'deal_value': -1}, {'deal_value': 'abc'}, {'status': 'meeting'},
                     {'splits': [{'user_id': self.john.id, 'share_pct': 50}]},
                     {'splits': [{'user_id': self.john.id, 'share_pct': 50}, {'user_id': self.john.id, 'share_pct': 50}]},
                     {'splits': [{'user_id': 999, 'share_pct': 100}]},
                     {'closed_on': '10/20/2026'}):
            self.assertEqual(self.client.put(url, json=body, headers=self.auth(self.admin)).status_code, 400, body)

    def test_rep_default_rate(self):
        url = f'/api/admin/reps/{self.mary.id}'
        self.assertEqual(self.client.patch(url, json={'commission_rate': 101}, headers=self.auth(self.admin)).status_code, 400)
        response = self.client.patch(url, json={'commission_rate': 12.5}, headers=self.auth(self.admin))
        self.assertEqual(response.get_json()['commission_rate'], 12.5)
        self.assertEqual(self.client.patch(url, json={'commission_rate': None}, headers=self.auth(self.admin))
                         .get_json()['commission_rate'], None)


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
