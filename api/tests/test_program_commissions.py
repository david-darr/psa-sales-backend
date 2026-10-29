"""Chris's pool policy, seasonal reporting, corrections and permissions."""
from decimal import Decimal

from api.tests.test_admin_sales import AdminSalesBase
from api import api as service
from api.program_commissions import calculate


class ProgramCommissionTests(AdminSalesBase):
    def payload(self):
        return dict(sales_school_id=self.won.id, season='Winter 2026/27', program='Soccer',
                    rep_id=self.john.id, sale_type='new', gross='10000.00', leagueapps=True,
                    cash_expenses='650.00', rep_payout='900.00')

    def create(self, **overrides):
        body = self.payload()
        body.update(overrides)
        return self.client.post('/api/admin/program-commissions', json=body, headers=self.auth(self.admin))

    def report(self, query=''):
        return self.client.get('/api/admin/program-commissions' + query, headers=self.auth(self.admin)).get_json()

    def test_new_pool_after_fees_and_expenses(self):
        response = self.create()
        self.assertEqual(response.status_code, 201, response.get_json())
        row = response.get_json()
        for key, expected in dict(leagueapps_fee=350, net=9650, commission_base=9000,
                                  pool_rate=15, pool=1350, rep_payout=900, director_remainder=450).items():
            self.assertEqual(row[key], expected, key)
        self.assertEqual(service.ProgramCommissionEvent.query.count(), 1)

    def test_renewal_and_no_fee(self):
        row = self.create(sale_type='renewal', leagueapps=False, cash_expenses=0, rep_payout=750).get_json()
        self.assertEqual(row['pool'], 750)
        self.assertEqual(row['director_remainder'], 0)
        self.assertEqual(row['leagueapps_fee'], 0)

    def test_missing_payout_is_unallocated_not_director_income(self):
        row = self.create(rep_payout=None).get_json()
        self.assertIsNone(row['director_remainder'])
        self.assertTrue(row['needs_review'])
        summary = self.report()['summary']
        self.assertEqual(summary['unallocated_pool'], 1350)
        self.assertEqual(summary['director_remainder'], 0)
        self.assertEqual(summary['needs_review'], 1)

    def test_zero_payout_allocates_full_pool_to_director(self):
        row = self.create(rep_payout=0).get_json()
        self.assertFalse(row['needs_review'])
        self.assertEqual(row['director_remainder'], 1350)

    def test_decimal_rounding(self):
        row = calculate('1.00', True, 0, 'new', '0.14')
        self.assertEqual(row['leagueapps_fee'], Decimal('0.04'))
        self.assertEqual(row['pool'], Decimal('0.14'))
        self.assertEqual(row['director_remainder'], Decimal('0.00'))

    def test_validation_does_not_create_records(self):
        for override in ({'gross': True}, {'gross': 'NaN'}, {'gross': -1}, {'gross': '1.001'},
                         {'cash_expenses': 10000}, {'rep_payout': 1350.01}, {'rep_payout': -1},
                         {'leagueapps': 'false'}, {'sale_type': 'other'}, {'rep_id': 999},
                         {'season': ''}, {'program': ' '}, {'gross': '10000000000'}, {'sale_type': []}):
            response = self.create(**override)
            self.assertEqual(response.status_code, 400, (override, response.get_json()))
        self.assertEqual(service.ProgramCommission.query.count(), 0)

    def test_seasons_and_programs_are_distinct_duplicate_is_blocked(self):
        self.assertEqual(self.create().status_code, 201)
        self.assertEqual(self.create(season=' winter   2026/27 ', program=' soccer ').status_code, 409)
        self.assertEqual(self.create(season='Spring 2027', sale_type='renewal', rep_payout=500).status_code, 201)
        self.assertEqual(self.create(program='Basketball').status_code, 201)
        self.assertEqual(self.report()['summary']['programs'], 3)
        self.assertEqual(self.report('?season=Spring+2027')['summary']['pool'], 675)

    def test_rep_and_season_totals_and_filter(self):
        self.create()
        self.create(rep_id=self.mary.id, season='Spring 2027', rep_payout=500)
        data = self.report()
        self.assertEqual(data['summary']['pool'], 2700)
        self.assertEqual(data['summary']['rep_payout'], 1400)
        self.assertEqual(data['summary']['director_remainder'], 1300)
        self.assertEqual(len(data['by_rep']), 2)
        self.assertEqual(len(data['by_season']), 2)
        self.assertEqual(self.report(f'?rep_id={self.mary.id}')['summary']['rep_payout'], 500)

    def test_revision_history_void_and_legacy_unchanged(self):
        self.won.deal_value = 12000
        service.db.session.commit()
        created = self.create().get_json()
        url = f"/api/admin/program-commissions/{created['id']}"
        body = self.payload()
        body.update(revision=1, rep_payout=1000, voided=True)
        updated = self.client.put(url, json=body, headers=self.auth(self.admin))
        self.assertEqual(updated.status_code, 200, updated.get_json())
        self.assertEqual(updated.get_json()['revision'], 2)
        self.assertEqual(self.client.put(url, json=body, headers=self.auth(self.admin)).status_code, 409)
        self.assertEqual(self.report()['summary']['programs'], 0)
        self.assertEqual(len(self.report()['records']), 1)
        history = self.client.get(url + '/history', headers=self.auth(self.admin)).get_json()
        self.assertEqual(len(history), 2)
        self.assertEqual(history[1]['before']['rep_payout'], 900)
        self.assertEqual(history[1]['after']['rep_payout'], 1000)
        self.assertEqual(service.db.session.get(service.SalesSchool, self.won.id).deal_value, 12000)

    def test_permission_boundaries_and_csv(self):
        created = self.create(program='=SOMEFORMULA()').get_json()
        for url in ('/api/admin/program-commissions', f"/api/admin/program-commissions/{created['id']}/history"):
            self.assertEqual(self.client.get(url).status_code, 401)
            self.assertEqual(self.client.get(url, headers=self.auth(self.john)).status_code, 403)
        self.assertEqual(self.client.post('/api/admin/program-commissions', json=self.payload(), headers=self.auth(self.john)).status_code, 403)
        self.assertEqual(self.client.put(f"/api/admin/program-commissions/{created['id']}", json=self.payload(), headers=self.auth(self.john)).status_code, 403)
        response = self.client.get('/api/admin/program-commissions?format=csv', headers=self.auth(self.admin))
        self.assertEqual(response.mimetype, 'text/csv')
        self.assertIn("'=SOMEFORMULA()", response.get_data(as_text=True))
