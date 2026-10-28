"""Closed-won accounts: stage rules, portfolio, map data, add-school and team admin toggle."""
import base64
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service  # noqa: E402
from api.portfolio import city_from_address, initials, set_school_status  # noqa: E402


def days_ago(days):
    return datetime.now(timezone.utc) - timedelta(days=days)


class PortfolioBase(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        User = service.User
        self.admin = User(name='Ricky Boss', email='ricky@example.test', admin=True, password_hash='x')
        self.john = User(name='John Smith', email='john@example.test', admin=False, password_hash='x')
        self.mary = User(name='Mary Jones', email='mary@example.test', admin=False, password_hash='x')
        self.idle = User(name='Zed Idle', email='zed@example.test', admin=False, password_hash='x')
        service.db.session.add_all([self.admin, self.john, self.mary, self.idle])
        service.db.session.flush()
        self.a = self.school('Alpha Prep', self.john, 'partner', closed_at=days_ago(10),
                             address='1 Main St, Fairfax, VA 22030', lat=38.85, lng=-77.3)
        self.b = self.school('Beta Academy', self.john, 'partner', closed_at=days_ago(200),
                             address='2 Oak Ave, Reston, VA 20190')
        self.c = self.school('Gamma Kids', self.john, 'former', closed_at=days_ago(400))
        self.d = self.school('Delta School', self.john, 'contacted')
        self.e = self.school('Echo School', self.john, 'not_interested')
        self.f = self.school('Foxtrot Prep', self.mary, 'partner', closed_at=days_ago(5), lat=38.9, lng=-77.1)
        self.g = self.school('Golf School', self.mary, 'pending')
        service.db.session.commit()
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def school(self, name, owner, status, **extra):
        school = service.SalesSchool(school_name=name, email=name.split()[0].lower() + '@example.test',
                                     school_type='preschool', user_id=owner.id, status=status, **extra)
        if extra.get('closed_at'):
            school.closed_by_id = owner.id
        service.db.session.add(school)
        return school

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}


class StageRuleTests(PortfolioBase):
    def test_former_is_a_valid_stage(self):
        self.assertIn('former', service.SCHOOL_STAGES)
        response = self.client.patch(f'/api/sales-schools/{self.d.id}', headers=self.auth(self.john),
                                     json={'status': 'former'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['status'], 'former')
        bad = self.client.patch(f'/api/sales-schools/{self.d.id}', headers=self.auth(self.john),
                                json={'status': 'nonsense'})
        self.assertEqual(bad.status_code, 400)

    def test_helper_stamps_once_and_keeps_date_through_former(self):
        school = service.SalesSchool(school_name='X', email='x@example.test', user_id=self.john.id, status='meeting')
        self.assertTrue(set_school_status(school, 'partner', self.admin.id))
        first = school.closed_at
        self.assertIsNotNone(first)
        self.assertEqual(school.closed_by_id, self.admin.id)
        set_school_status(school, 'former', self.john.id)
        self.assertEqual((school.closed_at, school.closed_by_id), (first, self.admin.id))
        set_school_status(school, 'partner', self.john.id)
        self.assertEqual((school.closed_at, school.closed_by_id), (first, self.admin.id))
        self.assertFalse(set_school_status(school, 'partner', self.john.id))

    def test_workspace_patch_sets_closed_at_for_the_acting_user(self):
        response = self.client.patch(f'/api/sales-schools/{self.d.id}', headers=self.auth(self.admin),
                                     json={'status': 'partner'})
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(body['closed_at'])
        self.assertEqual(body['closed_by_id'], self.admin.id)
        self.assertEqual(body['closed_by_name'], 'Ricky Boss')
        self.assertEqual(body['owner_name'], 'John Smith')
        stamp = body['closed_at']
        self.client.patch(f'/api/sales-schools/{self.d.id}', headers=self.auth(self.john), json={'status': 'former'})
        again = self.client.get(f'/api/sales-schools/{self.d.id}', headers=self.auth(self.john)).get_json()['school']
        self.assertEqual(again['status'], 'former')
        self.assertEqual(again['closed_at'], stamp)
        self.assertEqual(again['closed_by_id'], self.admin.id)

    def test_other_changes_do_not_touch_closed_at(self):
        response = self.client.patch(f'/api/sales-schools/{self.d.id}', headers=self.auth(self.john),
                                     json={'status': 'meeting'})
        self.assertIsNone(response.get_json()['closed_at'])

    def test_bulk_update_sets_closed_at(self):
        response = self.client.post('/api/crm/schools/bulk', headers=self.auth(self.john),
                                    json={'ids': [self.d.id, self.e.id], 'status': 'partner'})
        self.assertEqual(response.status_code, 200)
        for school in (self.d, self.e):
            service.db.session.refresh(school)
            self.assertIsNotNone(school.closed_at)
            self.assertEqual(school.closed_by_id, self.john.id)
        stamp = self.a.closed_at
        self.client.post('/api/crm/schools/bulk', headers=self.auth(self.admin),
                         json={'ids': [self.a.id], 'status': 'former'})
        service.db.session.refresh(self.a)
        self.assertEqual(self.a.closed_at, stamp)

    def test_finished_stages_get_no_followup(self):
        sent = service.SentEmail(school_name='Delta School', school_email='d@example.test', user_id=self.john.id,
                                 sales_school_id=self.d.id, sent_at=service.utc_now() - timedelta(days=9))
        service.db.session.add(sent)
        service.db.session.commit()
        self.assertIsNone(service.followup_eligibility_error(sent))
        for stage in ('partner', 'former', 'not_interested'):
            self.d.status = stage
            service.db.session.commit()
            self.assertIn('no follow-up', service.followup_eligibility_error(sent))
        overview = self.client.get('/api/crm/overview', headers=self.auth(self.john)).get_json()
        self.assertEqual(overview['due_followups'], 0)
        self.d.status = 'contacted'
        service.db.session.commit()
        overview = self.client.get('/api/crm/overview', headers=self.auth(self.john)).get_json()
        self.assertEqual(overview['due_followups'], 1)

    def test_small_helpers(self):
        self.assertEqual(initials('John Smith'), 'JS')
        self.assertEqual(initials('Cher'), 'CH')
        self.assertEqual(city_from_address('1 Main St, Fairfax, VA 22030'), 'Fairfax')
        self.assertEqual(city_from_address('1 Main St, Fairfax, VA 22030, USA'), 'Fairfax')
        self.assertEqual(city_from_address('12 Elm Rd, Ashburn'), 'Ashburn')
        self.assertIsNone(city_from_address('12 Elm Rd'))
        self.assertIsNone(city_from_address(None))


class PortfolioRouteTests(PortfolioBase):
    def test_admin_sees_every_rep_sorted_by_active_then_name(self):
        body = self.client.get('/api/crm/portfolio', headers=self.auth(self.admin)).get_json()
        self.assertEqual(body['scope'], 'all')
        self.assertEqual([rep['name'] for rep in body['reps']],
                         ['John Smith', 'Mary Jones', 'Ricky Boss', 'Zed Idle'])
        self.assertEqual(body['totals'], {'reps': 4, 'total_schools': 7, 'active_clients': 3,
                                          'former_clients': 1, 'in_pipeline': 2, 'closed_last_90': 2})
        john = body['reps'][0]
        self.assertEqual(john['counts'], {'total': 5, 'pipeline': 1, 'active': 2, 'former': 1})
        self.assertEqual((john['closed_total'], john['closed_last_90'], john['initials']), (3, 1, 'JS'))
        self.assertEqual([a['school_name'] for a in john['accounts']], ['Alpha Prep', 'Beta Academy', 'Gamma Kids'])
        first = john['accounts'][0]
        self.assertEqual(set(first), {'id', 'school_name', 'status', 'school_type', 'address', 'city', 'lat', 'lng',
                                      'closed_at', 'last_activity_at', 'contact_name'})
        self.assertEqual((first['city'], first['lat'], first['lng']), ('Fairfax', 38.85, -77.3))
        self.assertIn('admin', john)
        self.assertIn('email', john)
        idle = body['reps'][3]
        self.assertEqual((idle['accounts'], idle['counts']['total'], idle['closed_total']), ([], 0, 0))

    def test_non_admin_sees_only_themselves(self):
        body = self.client.get('/api/crm/portfolio', headers=self.auth(self.mary)).get_json()
        self.assertEqual(body['scope'], 'self')
        self.assertEqual([rep['id'] for rep in body['reps']], [self.mary.id])
        self.assertEqual(body['totals']['reps'], 1)
        self.assertEqual(body['totals']['total_schools'], 2)
        names = [a['school_name'] for rep in body['reps'] for a in rep['accounts']]
        self.assertEqual(names, ['Foxtrot Prep'])
        self.assertEqual(self.client.get('/api/crm/portfolio').status_code, 401)

    def test_admin_can_narrow_to_self_with_scope_mine(self):
        body = self.client.get('/api/crm/portfolio?scope=mine', headers=self.auth(self.admin)).get_json()
        self.assertEqual(body['scope'], 'self')
        self.assertEqual([rep['id'] for rep in body['reps']], [self.admin.id])

    def test_last_activity_uses_notes_and_sent_email(self):
        when = service.utc_now() - timedelta(days=2)
        service.db.session.add(service.SchoolActivity(sales_school_id=self.a.id, actor_id=self.john.id,
                                                      kind='note', detail='Called', created_at=when))
        service.db.session.add(service.SentEmail(school_name='Alpha Prep', school_email='a@example.test',
                                                 user_id=self.john.id, sales_school_id=self.a.id,
                                                 sent_at=service.utc_now() - timedelta(days=6)))
        service.db.session.commit()
        body = self.client.get('/api/crm/portfolio', headers=self.auth(self.john)).get_json()
        accounts = {a['school_name']: a for a in body['reps'][0]['accounts']}
        self.assertTrue(accounts['Alpha Prep']['last_activity_at'].startswith(when.date().isoformat()))
        self.assertIsNone(accounts['Beta Academy']['last_activity_at'])

    def test_portfolio_uses_geocode_cache_when_school_has_no_coordinates(self):
        service.db.session.add(service.GeocodedAddress(
            address_key=service.normalize_name(self.b.address), lat=38.95, lng=-77.35))
        service.db.session.commit()
        body = self.client.get('/api/crm/portfolio', headers=self.auth(self.john)).get_json()
        beta = [a for a in body['reps'][0]['accounts'] if a['school_name'] == 'Beta Academy'][0]
        self.assertEqual((beta['lat'], beta['lng']), (38.95, -77.35))

    def test_query_count_does_not_grow_with_reps(self):
        from sqlalchemy import event
        counts = []
        for extra in (0, 5):
            for index in range(extra):
                user = service.User(name=f'Rep {index}', email=f'rep{index}@example.test', password_hash='x')
                service.db.session.add(user)
                service.db.session.flush()
                self.school(f'Closed {index}', user, 'partner', closed_at=days_ago(index))
            service.db.session.commit()
            seen = []
            listener = lambda conn, cursor, statement, *args: seen.append(statement)  # noqa: E731
            event.listen(service.db.engine, 'before_cursor_execute', listener)
            try:
                self.client.get('/api/crm/portfolio', headers=self.auth(self.admin))
            finally:
                event.remove(service.db.engine, 'before_cursor_execute', listener)
            counts.append(len(seen))
        self.assertEqual(counts[0], counts[1])


class MapAccountRouteTests(PortfolioBase):
    def test_defaults_to_closed_accounts_with_coordinates(self):
        body = self.client.get('/api/crm/map-accounts', headers=self.auth(self.admin)).get_json()
        # Alpha and Foxtrot have coordinates; Beta (address only) and Gamma (nothing) do not.
        self.assertEqual(sorted(a['school_name'] for a in body['accounts']), ['Alpha Prep', 'Foxtrot Prep'])
        self.assertEqual(body['unlocated'], 2)
        self.assertEqual([(r['name'], r['count']) for r in body['reps']], [('John Smith', 3), ('Mary Jones', 1)])
        alpha = [a for a in body['accounts'] if a['school_name'] == 'Alpha Prep'][0]
        self.assertEqual(set(alpha), {'id', 'school_name', 'address', 'status', 'school_type', 'owner_id',
                                      'owner_name', 'lat', 'lng', 'closed_at'})
        self.assertEqual(alpha['owner_name'], 'John Smith')

    def test_geocode_cache_fallback_and_owner_and_stage_filters(self):
        service.db.session.add(service.GeocodedAddress(
            address_key=service.normalize_name(self.b.address), lat=38.95, lng=-77.35))
        service.db.session.commit()
        url = f'/api/crm/map-accounts?owner={self.john.id}&stages=partner'
        body = self.client.get(url, headers=self.auth(self.admin)).get_json()
        self.assertEqual(sorted(a['school_name'] for a in body['accounts']), ['Alpha Prep', 'Beta Academy'])
        self.assertEqual(body['unlocated'], 0)
        # The rep list ignores the owner filter so a dropdown keeps every option.
        self.assertEqual(len(body['reps']), 2)
        everything = self.client.get('/api/crm/map-accounts?stages=contacted,pending', headers=self.auth(self.admin)).get_json()
        self.assertEqual(everything['accounts'], [])
        self.assertEqual(everything['unlocated'], 2)

    def test_non_admin_cannot_see_other_reps(self):
        body = self.client.get('/api/crm/map-accounts', headers=self.auth(self.mary)).get_json()
        self.assertEqual([a['school_name'] for a in body['accounts']], ['Foxtrot Prep'])
        self.assertEqual([r['id'] for r in body['reps']], [self.mary.id])
        other = self.client.get(f'/api/crm/map-accounts?owner={self.john.id}', headers=self.auth(self.mary)).get_json()
        self.assertEqual(other['accounts'], [])

    def test_invalid_parameters(self):
        self.assertEqual(self.client.get('/api/crm/map-accounts?stages=bogus', headers=self.auth(self.admin)).status_code, 400)
        self.assertEqual(self.client.get('/api/crm/map-accounts?owner=abc', headers=self.auth(self.admin)).status_code, 400)

    def test_locate_geocodes_in_batches_and_persists(self):
        calls = []

        def fake(address):
            calls.append(address)
            return (38.8, -77.2) if 'Reston' in address else (None, None)
        extra = self.school('No Address', self.john, 'partner', closed_at=days_ago(1))
        service.db.session.commit()
        with patch.object(service, 'geocode_address', side_effect=fake):
            first = self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.admin), json={'limit': 1})
            self.assertEqual(first.get_json(), {'located': 1, 'remaining': 0})
        service.db.session.refresh(self.b)
        self.assertEqual((self.b.lat, self.b.lng), (38.8, -77.2))
        self.assertEqual(calls, [self.b.address])
        # Schools without an address cannot be located and do not count as remaining.
        service.db.session.refresh(extra)
        self.assertIsNone(extra.lat)
        with patch.object(service, 'geocode_address', side_effect=fake) as geocode:
            again = self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.admin), json={}).get_json()
            self.assertEqual(again, {'located': 0, 'remaining': 0})
            geocode.assert_not_called()

    def test_locate_failures_stop_looping_and_limit_is_capped(self):
        for index in range(60):
            self.school(f'Bulk {index}', self.mary, 'pending', address=f'{index} Nowhere Rd, Void, VA')
        service.db.session.commit()
        with patch.object(service, 'geocode_address', return_value=(None, None)) as geocode:
            first = self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.admin),
                                     json={'limit': 500}).get_json()
            self.assertEqual(geocode.call_count, 50)
            self.assertEqual(first['located'], 0)
            # 60 bulk + Beta (address, no coords) = 61 candidates, 50 handled.
            self.assertEqual(first['remaining'], 11)
            second = self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.admin),
                                      json={'limit': 50}).get_json()
            self.assertEqual(second['remaining'], 0)
            self.assertEqual(geocode.call_count, 61)

    def test_locate_is_scoped_and_validated(self):
        with patch.object(service, 'geocode_address', return_value=(1.0, 2.0)) as geocode:
            response = self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.mary), json={'limit': 5})
            self.assertEqual(response.get_json(), {'located': 0, 'remaining': 0})  # Mary's schools have no address
            geocode.assert_not_called()
            self.assertEqual(self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.mary),
                                              json={'limit': 'x'}).status_code, 400)
            self.assertEqual(self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.mary),
                                              json={'limit': 0}).status_code, 400)
        service.db.session.refresh(self.b)
        self.assertIsNone(self.b.lat)

    def test_locate_reuses_cached_coordinates_without_the_provider(self):
        service.db.session.add(service.GeocodedAddress(
            address_key=service.normalize_name(self.b.address), lat=38.7, lng=-77.0,
            checked_at=service.utc_now() - timedelta(days=400)))
        service.db.session.commit()
        with patch.object(service, 'geocode_address') as geocode:
            body = self.client.post('/api/crm/map-accounts/locate', headers=self.auth(self.admin), json={}).get_json()
            geocode.assert_not_called()
        self.assertEqual(body['located'], 1)


class CrmSchoolsAndTeamTests(PortfolioBase):
    def test_stage_list_and_closed_sort(self):
        body = self.client.get('/api/crm/schools?stage=partner,former&sort=closed', headers=self.auth(self.admin)).get_json()
        self.assertEqual([row['school_name'] for row in body['items']],
                         ['Foxtrot Prep', 'Alpha Prep', 'Beta Academy', 'Gamma Kids'])
        self.assertEqual(body['items'][0]['closed_by_name'], 'Mary Jones')
        self.assertTrue(body['items'][0]['closed_at'])
        mixed = self.client.get('/api/crm/schools?stage=former,pending&sort=closed', headers=self.auth(self.admin)).get_json()
        self.assertEqual([row['school_name'] for row in mixed['items']], ['Gamma Kids', 'Golf School'])
        self.assertEqual(self.client.get('/api/crm/schools?stage=partner,bogus', headers=self.auth(self.admin)).status_code, 400)
        self.assertEqual(self.client.get('/api/crm/schools?stage=former', headers=self.auth(self.john)).get_json()['total'], 1)
        self.assertEqual(self.client.get('/api/crm/schools?stage=former', headers=self.auth(self.mary)).get_json()['total'], 0)

    def test_admin_toggle_returns_team_row_shape(self):
        listing = {row['id']: row for row in self.client.get('/api/crm/team', headers=self.auth(self.admin)).get_json()}
        response = self.client.patch(f'/api/crm/team/{self.john.id}', headers=self.auth(self.admin), json={'admin': True})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body['admin'])
        self.assertEqual(body['role'], 'Administrator')
        self.assertEqual(set(body), set(listing[self.john.id]))
        self.assertEqual(body['schools'], 5)
        again = self.client.patch(f'/api/crm/team/{self.john.id}', headers=self.auth(self.admin), json={'admin': False})
        self.assertFalse(again.get_json()['admin'])
        self.assertEqual(again.get_json()['role'], 'Sales representative')

    def test_toggle_permissions_and_validation(self):
        path = f'/api/crm/team/{self.mary.id}'
        self.assertEqual(self.client.patch(path, headers=self.auth(self.john), json={'admin': True}).status_code, 403)
        service.db.session.refresh(self.mary)
        self.assertFalse(self.mary.admin)
        self.assertEqual(self.client.patch(f'/api/crm/team/{self.john.id}', headers=self.auth(self.john),
                                           json={'admin': True}).status_code, 403)
        self.assertEqual(self.client.patch(f'/api/crm/team/{self.admin.id}', headers=self.auth(self.admin),
                                           json={'admin': False}).status_code, 400)
        service.db.session.refresh(self.admin)
        self.assertTrue(self.admin.admin)
        self.assertEqual(self.client.patch(path, headers=self.auth(self.admin), json={'admin': 'yes'}).status_code, 400)
        self.assertEqual(self.client.patch(path, headers=self.auth(self.admin), json={}).status_code, 400)
        self.assertEqual(self.client.patch('/api/crm/team/9999', headers=self.auth(self.admin), json={'admin': True}).status_code, 404)
        self.assertEqual(self.client.patch(path, json={'admin': True}).status_code, 401)


class AddSchoolFinderTests(PortfolioBase):
    def post(self, user, **body):
        return self.client.post('/api/add-school', headers=self.auth(user), json=body)

    def test_blank_email_is_allowed_for_finder_leads_and_stores_extras(self):
        response = self.post(self.john, school_name='Finder School', email='', place_id='pid-1', lat=38.9, lng=-77.1,
                             phone='555-1234', website='https://finder.example.test', address='9 Pine Rd, Fairfax')
        self.assertEqual(response.status_code, 201)
        school = service.db.session.get(service.SalesSchool, response.get_json()['id'])
        self.assertEqual((school.email, school.place_id, school.lat, school.lng), ('', 'pid-1', 38.9, -77.1))
        self.assertEqual((school.phone, school.website), ('555-1234', 'https://finder.example.test'))
        by_source = self.post(self.john, school_name='Another', source='finder')
        self.assertEqual(by_source.status_code, 201)

    def test_manual_add_still_requires_a_valid_email(self):
        self.assertEqual(self.post(self.john, school_name='Manual', email='').status_code, 400)
        self.assertEqual(self.post(self.john, school_name='Manual').status_code, 400)
        self.assertEqual(self.post(self.john, school_name='Manual', email='nope').status_code, 400)
        self.assertEqual(self.post(self.john, school_name='Finder', email='nope', place_id='p').status_code, 400)
        self.assertEqual(self.post(self.john, school_name='Manual', email='ok@example.test').status_code, 201)

    def test_dedupes_on_place_id_then_name_and_address(self):
        first = self.post(self.john, school_name='Dupe School', place_id='dup-1', address='5 Elm St, Reston, VA', lat=38.9, lng=-77.1)
        self.assertEqual(first.status_code, 201)
        existing_id = first.get_json()['id']
        by_place = self.post(self.mary, school_name='Totally Different', place_id='dup-1')
        self.assertEqual(by_place.status_code, 409)
        body = by_place.get_json()
        self.assertEqual((body['existing_id'], body['owner_name']), (existing_id, 'John Smith'))
        self.assertIn('error', body)
        self.assertIsNone(body['school_id'])  # Mary does not own it
        by_name = self.post(self.mary, school_name='dupe school!', place_id='other', address='5 Elm St, Reston')
        self.assertEqual(by_name.status_code, 409)
        self.assertEqual(by_name.get_json()['existing_id'], existing_id)
        own = self.post(self.john, school_name='Dupe School', place_id='dup-1')
        self.assertEqual(own.get_json()['school_id'], existing_id)
        by_email = self.post(self.mary, school_name='Brand New', email=self.a.email)
        self.assertEqual(by_email.status_code, 409)
        self.assertEqual(by_email.get_json()['owner_name'], 'John Smith')

    def test_blank_email_school_is_stored_and_listed(self):
        self.post(self.john, school_name='Phone Only', place_id='po-1')
        rows = self.client.get('/api/my-schools', headers=self.auth(self.john)).get_json()
        row = [item for item in rows if item['school_name'] == 'Phone Only'][0]
        self.assertEqual((row['email'], row['all_emails'], row['place_id']), ('', [''], 'po-1'))
        for key in ('closed_at', 'closed_by_id', 'closed_by_name', 'owner_name', 'lat', 'lng', 'place_id'):
            self.assertIn(key, row)


if __name__ == '__main__':
    unittest.main()
