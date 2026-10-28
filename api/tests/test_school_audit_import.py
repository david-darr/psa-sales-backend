"""PSA school audit importer: stage mapping, owner matching, upserts and dry runs."""
import base64
import csv
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service  # noqa: E402
from api.maintenance import import_school_audit as audit  # noqa: E402


class StageTests(unittest.TestCase):
    def test_stage_mapping(self):
        cases = {('Current client', ''): 'partner', ('', 'Schools currently in'): 'partner',
                 ('', 'Schools in contact'): 'contacted', ('potential client', ''): 'contacted',
                 ('Current client', 'Schools in contact'): 'partner', ('Former', ''): 'former',
                 ('Meeting set', ''): 'meeting', ('no response', ''): 'contacted',
                 ('Not interested', ''): 'not_interested', ('Leadership academy', ''): 'contacted'}
        for (raw, sheet), stage in cases.items():
            self.assertEqual(audit.stage_for(raw, sheet), stage, (raw, sheet))


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.db.create_all()
        self.admin = service.User(name='David Darr', email='david@example.test', admin=True, password_hash='x')
        self.rep = service.User(name='Chris Garabito', email='chris@example.test', password_hash='x')
        service.db.session.add_all([self.admin, self.rep])
        service.db.session.flush()
        service.db.session.add(service.SalesSchool(school_name='Alpha Prep', email='alpha@example.test',
                                                   school_type='preschool', user_id=self.admin.id, status='contacted'))
        service.db.session.commit()
        self.admin_id, self.rep_id = self.admin.id, self.rep.id
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def write(self, rows):
        path = os.path.join(self.dir, 'audit.csv')
        with open(path, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(['School Name', 'Email', 'Sales Rep', 'Status', 'Deal Value'])
            writer.writerows(rows)
        return path

    def run_import(self, path, apply):
        out = StringIO()
        args = [path, '--fallback-owner', 'david@example.test'] + (['--apply'] if apply else [])
        with redirect_stdout(out):
            audit.main(args)
        service.db.session.remove()
        return out.getvalue()

    def test_dry_run_writes_nothing(self):
        path = self.write([['Beta Academy', 'beta@example.test', 'Chris Garabito', 'Current client', '$5,000']])
        output = self.run_import(path, apply=False)
        self.assertIn('DRY RUN', output)
        self.assertEqual(service.SalesSchool.query.count(), 1)

    def test_apply_upserts_and_never_downgrades(self):
        path = self.write([
            ['Beta Academy', 'beta@example.test', 'Chris Garabito', 'Current client', '$5,000'],
            ['ALPHA PREP', 'alpha@example.test', 'chris@example.test', 'In contact', ''],
            ['Gamma Kids', '', 'Pat Unknown', 'In contact', ''],
            ['Beta Academy', 'beta@example.test', 'Chris Garabito', 'Current client', ''],
        ])
        output = self.run_import(path, apply=True)
        self.assertIn('Pat Unknown: 1', output)
        schools = {s.school_name: s for s in service.SalesSchool.query.all()}
        self.assertEqual(len(schools), 3)
        beta = schools['Beta Academy']
        self.assertEqual((beta.status, beta.user_id, float(beta.deal_value)), ('partner', self.rep_id, 5000.0))
        self.assertIsNotNone(beta.closed_at)
        self.assertEqual(schools['Alpha Prep'].user_id, self.rep_id)
        gamma = schools['Gamma Kids']
        self.assertEqual(gamma.user_id, self.admin_id)
        self.assertIn('Audit rep: Pat Unknown', gamma.notes)

        # Re-running is idempotent and does not downgrade a client.
        downgrade = self.write([['Beta Academy', 'beta@example.test', 'Chris Garabito', 'In contact', '']])
        self.run_import(downgrade, apply=True)
        self.assertEqual(service.SalesSchool.query.filter_by(school_name='Beta Academy').one().status, 'partner')
        self.assertEqual(service.SalesSchool.query.count(), 3)


if __name__ == '__main__':
    unittest.main()
