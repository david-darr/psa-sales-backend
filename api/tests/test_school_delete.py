"""Deleting schools: reps delete only their own, administrators delete any."""
import base64
import os
import unittest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service  # noqa: E402

URL = '/api/crm/schools/delete'


class SchoolDeleteTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        User = service.User
        self.admin = User(name='Ada Admin', email='ada@example.test', admin=True, password_hash='x')
        self.john = User(name='John Rep', email='john@example.test', password_hash='x')
        self.mary = User(name='Mary Rep', email='mary@example.test', password_hash='x')
        service.db.session.add_all([self.admin, self.john, self.mary])
        service.db.session.flush()
        self.johns = self.school('Alpha Prep', self.john)
        self.johns2 = self.school('Beta Academy', self.john)
        self.marys = self.school('Gamma Kids', self.mary)
        service.db.session.flush()
        service.db.session.add(service.SchoolActivity(sales_school_id=self.johns.id, actor_id=self.john.id,
                                                      kind='note', detail='Called'))
        service.db.session.add(service.SalesTask(title='Follow up', user_id=self.john.id, school_id=self.johns.id))
        service.db.session.add(service.SentEmail(school_name='Alpha Prep', school_email='alpha@example.test',
                                                 user_id=self.john.id, sales_school_id=self.johns.id))
        service.db.session.commit()
        self.ids = {name: getattr(self, name).id for name in ('johns', 'johns2', 'marys')}
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def school(self, name, owner):
        school = service.SalesSchool(school_name=name, email=name.split()[0].lower() + '@example.test',
                                     school_type='preschool', user_id=owner.id, status='contacted')
        service.db.session.add(school)
        return school

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def remaining(self):
        return {s.id for s in service.SalesSchool.query.all()}

    def test_rep_deletes_own_school_and_history_is_kept(self):
        response = self.client.post(URL, json={'ids': [self.ids['johns']]}, headers=self.auth(self.john))
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['names'], ['Alpha Prep'])
        self.assertNotIn(self.ids['johns'], self.remaining())
        self.assertEqual(service.SchoolActivity.query.count(), 0)
        task = service.SalesTask.query.one()
        self.assertIsNone(task.school_id)
        self.assertEqual(task.version, 2)
        self.assertIsNone(service.SentEmail.query.one().sales_school_id)

    def test_rep_cannot_delete_someone_elses_school(self):
        response = self.client.post(URL, json={'ids': [self.ids['johns2'], self.ids['marys']]},
                                    headers=self.auth(self.john))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.remaining()), 3)  # all or nothing

    def test_admin_deletes_anyones_schools(self):
        response = self.client.post(URL, json={'ids': [self.ids['johns2'], self.ids['marys']]},
                                    headers=self.auth(self.admin))
        self.assertEqual(response.get_json()['deleted'], 2)
        self.assertEqual(self.remaining(), {self.ids['johns']})

    def test_validation_and_missing_schools(self):
        for body in ({}, {'ids': []}, {'ids': ['1']}, {'ids': list(range(1, 102))}):
            self.assertEqual(self.client.post(URL, json=body, headers=self.auth(self.admin)).status_code, 400)
        self.assertEqual(self.client.post(URL, json={'ids': [999]}, headers=self.auth(self.admin)).status_code, 404)

    def test_school_in_a_sending_batch_is_blocked(self):
        batch = service.OutreachBatch(user_id=self.john.id, kind='intro', status='running')
        service.db.session.add(batch)
        service.db.session.flush()
        service.db.session.add(service.OutreachRecipient(batch_id=batch.id, school_id=self.ids['johns'],
                                                         school_name='Alpha Prep', status='queued'))
        service.db.session.commit()
        response = self.client.post(URL, json={'ids': [self.ids['johns']]}, headers=self.auth(self.john))
        self.assertEqual(response.status_code, 409)
        self.assertIn(self.ids['johns'], self.remaining())


if __name__ == '__main__':
    unittest.main()
