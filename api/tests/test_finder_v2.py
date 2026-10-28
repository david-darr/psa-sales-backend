"""Finder v2: parallel search, saved-school flags, details cache and batch save. No network."""
import base64
import os
import unittest
from unittest.mock import Mock, patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service  # noqa: E402
from api import finder  # noqa: E402

CENTER = (38.85, -77.30)


def place(place_id, name, lat, lng, vicinity='1 Main St, Fairfax', **extra):
    return {'place_id': place_id, 'name': name, 'vicinity': vicinity,
            'geometry': {'location': {'lat': lat, 'lng': lng}}, **extra}


def reply(body):
    return Mock(**{'json.return_value': body, 'raise_for_status.return_value': None})


class FinderBase(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        finder._details_cache.clear()
        self.admin = service.User(name='Ricky', email='ricky@example.test', admin=True, password_hash='x')
        self.john = service.User(name='John', email='john@example.test', admin=False, password_hash='x')
        self.mary = service.User(name='Mary', email='mary@example.test', admin=False, password_hash='x')
        service.db.session.add_all([self.admin, self.john, self.mary])
        service.db.session.commit()
        self.client = service.app.test_client()
        self.patches = [
            patch.object(service, 'load_PSA_school_sheet', return_value=[]),
            patch.object(service, 'split_sheet_schools', return_value=([], [], [])),
            patch.object(service, 'geocode_address', return_value=CENTER),
        ]
        self.geocode = None
        for item in self.patches:
            started = item.start()
            if item.attribute == 'geocode_address':
                self.geocode = started
        self.addCleanup(lambda: [item.stop() for item in self.patches])

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def auth(self, user):
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(user.id))}

    def search(self, user=None, **body):
        return self.client.post('/api/find-schools', headers=self.auth(user or self.john), json=body)


class FindSchoolsTests(FinderBase):
    def test_merges_keywords_dedupes_sorts_by_distance_and_flags_saved(self):
        saved = service.SalesSchool(school_name='Near Montessori', email='', school_type='private',
                                    user_id=self.mary.id, place_id='p-near', address='1 Main St, Fairfax')
        by_name = service.SalesSchool(school_name='Far Elementary', email='', school_type='elementary',
                                      user_id=self.john.id, address='9 Far Rd, Fairfax, VA 22030')
        service.db.session.add_all([saved, by_name])
        service.db.session.commit()
        pages = {
            'preschool': [place('p-far', 'Far Elementary', 38.90, -77.30, '9 Far Rd, Fairfax', rating=4.5,
                                user_ratings_total=12, types=['school']),
                          place('p-near', 'Near Montessori', 38.851, -77.301)],
            'montessori': [place('p-near', 'Near Montessori', 38.851, -77.301),
                           place('p-mid', 'Mid Preschool', 38.87, -77.31)],
        }
        seen = []

        def fake_get(url, params=None, timeout=None):
            seen.append(params)
            return reply({'status': 'OK', 'results': pages[params['keyword']]})
        with patch.object(service.requests, 'get', side_effect=fake_get):
            response = self.search(address='Fairfax', keywords=['preschool', 'montessori'], radius_km=5)
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['radius_km'], 5)
        self.assertEqual(body['location'], {'lat': CENTER[0], 'lng': CENTER[1], 'label': 'Fairfax'})
        self.assertEqual([item['place_id'] for item in body['schools']], ['p-near', 'p-mid', 'p-far'])
        self.assertEqual({p['radius'] for p in seen}, {5000})
        near, mid, far = body['schools']
        self.assertEqual(set(near), {'place_id', 'school_name', 'address', 'lat', 'lng', 'distance_km', 'rating',
                                     'user_ratings_total', 'types', 'already_saved', 'saved_school_id', 'owner_name',
                                     'name', 'assigned', 'sales_school_id'})
        self.assertTrue(near['already_saved'])
        self.assertEqual(near['owner_name'], 'Mary')
        self.assertIsNone(near['saved_school_id'])  # John does not own it
        self.assertFalse(mid['already_saved'])
        self.assertIsNone(mid['owner_name'])
        self.assertTrue(far['already_saved'])  # matched on name + address, no place_id stored
        self.assertEqual(far['saved_school_id'], by_name.id)
        self.assertEqual((far['rating'], far['user_ratings_total']), (4.5, 12))
        self.assertAlmostEqual(far['distance_km'], 5.56, places=1)
        self.assertEqual(sorted(item['distance_km'] for item in body['schools']), [i['distance_km'] for i in body['schools']])
        self.assertEqual(self.geocode.call_count, 1)

    def test_admin_sees_saved_school_ids_for_every_rep(self):
        saved = service.SalesSchool(school_name='Near', email='', user_id=self.mary.id, place_id='p1')
        service.db.session.add(saved)
        service.db.session.commit()
        with patch.object(service.requests, 'get', return_value=reply({'results': [place('p1', 'Near', 38.85, -77.3)]})):
            body = self.search(user=self.admin, address='Fairfax', keywords='school').get_json()
        self.assertEqual(body['schools'][0]['saved_school_id'], saved.id)

    def test_lat_lng_skip_geocoding_and_keyword_string_is_split(self):
        seen = []

        def fake_get(url, params=None, timeout=None):
            seen.append(params)
            return reply({'results': []})
        with patch.object(service.requests, 'get', side_effect=fake_get):
            response = self.search(lat=38.8, lng=-77.2, keywords='day care, preschool', types=['school', 'preschool'])
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.geocode.assert_not_called()
        self.assertEqual(body['location'], {'lat': 38.8, 'lng': -77.2, 'label': '38.8000, -77.2000'})
        self.assertEqual(sorted((p['keyword'], p['type']) for p in seen),
                         [('day care', 'preschool'), ('day care', 'school'), ('preschool', 'preschool'), ('preschool', 'school')])
        self.assertEqual(body['radius_km'], 8)
        self.assertIsNone(body['next_page_token'])
        self.assertEqual(body['schools'], [])

    def test_old_request_body_still_works(self):
        with patch.object(service.requests, 'get', return_value=reply({'results': [place('n', 'Oak School', 38.9, -77.2)]})):
            response = self.search(address='Fairfax', keywords=['preschool'])
        school = response.get_json()['schools'][0]
        self.assertEqual((school['name'], school['school_name'], school['place_id']), ('Oak School',) * 2 + ('n',))

    def test_partner_sheet_schools_are_still_excluded(self):
        with patch.object(service, 'split_sheet_schools', return_value=([{'name': 'PSA Academy'}], [], [])), \
                patch.object(service.requests, 'get', return_value=reply({'results': [
                    place('k', 'PSA Academy', 38.9, -77.2), place('n', 'Oak School', 38.9, -77.2)]})):
            body = self.search(address='Fairfax', keywords=['x']).get_json()
        self.assertEqual([item['place_id'] for item in body['schools']], ['n'])

    def test_radius_is_clamped_and_validated(self):
        with patch.object(service.requests, 'get', return_value=reply({'results': []})) as get:
            self.assertEqual(self.search(address='Fairfax', keywords='a', radius_km=500).get_json()['radius_km'], 40)
            self.assertEqual(get.call_args.kwargs['params']['radius'], 40000)
            self.assertEqual(self.search(address='Fairfax', keywords='a', radius_km=0).get_json()['radius_km'], 1)
        self.assertEqual(self.search(address='Fairfax', radius_km='far').status_code, 400)

    def test_input_validation(self):
        for body in ({}, {'address': ''}, {'address': 'x' * 501}, {'lat': 1}, {'lat': 'a', 'lng': 2},
                     {'lat': 91, 'lng': 0}, {'address': 'Fairfax', 'keywords': []},
                     {'address': 'Fairfax', 'keywords': ['a'] * 7}, {'address': 'Fairfax', 'keywords': [3]},
                     {'address': 'Fairfax', 'types': ['Bad Type!']}, {'address': 'Fairfax', 'page_token': 'garbage'},
                     {'address': 'Fairfax', 'page_token': 5}):
            self.assertEqual(self.search(**body).status_code, 400, body)
        self.assertEqual(self.client.post('/api/find-schools', json={'address': 'x'}).status_code, 401)

    def test_address_not_found_and_provider_failures(self):
        self.geocode.return_value = (None, None)
        self.assertEqual(self.search(address='Nowhere').status_code, 404)
        self.geocode.return_value = CENTER
        with patch.object(service.requests, 'get', return_value=reply({'status': 'REQUEST_DENIED', 'results': []})):
            self.assertEqual(self.search(address='Fairfax', keywords='a').status_code, 502)
        with patch.object(service.requests, 'get', side_effect=service.requests.ConnectionError('boom key=SECRET')):
            with patch.object(service.app.logger, 'warning') as warn:
                response = self.search(address='Fairfax', keywords='a')
        self.assertEqual(response.status_code, 502)
        self.assertNotIn('SECRET', str(warn.call_args_list))
        self.assertNotIn('SECRET', response.get_data(as_text=True))

    def test_partial_provider_failure_still_returns_the_rest(self):
        def fake_get(url, params=None, timeout=None):
            if params['keyword'] == 'bad':
                return reply({'status': 'OVER_QUERY_LIMIT'})
            return reply({'results': [place('ok', 'Fine School', 38.9, -77.2)]})
        with patch.object(service.requests, 'get', side_effect=fake_get):
            body = self.search(address='Fairfax', keywords=['bad', 'good']).get_json()
        self.assertEqual([item['place_id'] for item in body['schools']], ['ok'])

    def test_pagination_token_round_trip(self):
        calls = []

        def fake_get(url, params=None, timeout=None):
            calls.append(dict(params))
            if 'pagetoken' in params:
                if params['pagetoken'] == 'g-a':
                    return reply({'results': [place('p2', 'Second Page', 38.86, -77.3)]})
                return reply({'results': [place('p3', 'Third Page', 38.87, -77.3)], 'next_page_token': None})
            if params['keyword'] == 'a':
                return reply({'results': [place('p1', 'First Page', 38.85, -77.3)], 'next_page_token': 'g-a'})
            return reply({'results': [], 'next_page_token': 'g-b'})
        with patch.object(service.requests, 'get', side_effect=fake_get):
            first = self.search(address='Fairfax', keywords=['a', 'b'], radius_km=3).get_json()
            token = first['next_page_token']
            self.assertTrue(token)
            self.geocode.reset_mock()
            second = self.search(address='ignored', keywords=['zzz'], page_token=token).get_json()
        self.geocode.assert_not_called()
        self.assertEqual([item['place_id'] for item in first['schools']], ['p1'])
        self.assertEqual(sorted(item['place_id'] for item in second['schools']), ['p2', 'p3'])
        self.assertIsNone(second['next_page_token'])
        self.assertEqual(second['radius_km'], 3)
        self.assertEqual(second['location']['label'], 'Fairfax')
        paged = [c for c in calls if 'pagetoken' in c]
        self.assertEqual(sorted(c['pagetoken'] for c in paged), ['g-a', 'g-b'])
        for call in paged:
            self.assertEqual(set(call), {'pagetoken', 'key'})

    def test_new_page_token_is_retried_until_the_provider_accepts_it(self):
        token = finder.encode_page_token({'lat': 1.0, 'lng': 2.0, 'r': 8, 'label': 'x', 't': [['a', 'school', 'g1']]})
        answers = iter([reply({'status': 'INVALID_REQUEST'}), reply({'results': [place('p', 'Late', 1.0, 2.0)]})])
        sleeps = []
        with patch.object(service.requests, 'get', side_effect=lambda *a, **k: next(answers)), \
                patch.object(service.time, 'sleep', side_effect=sleeps.append):
            body = self.search(page_token=token).get_json()
        self.assertEqual([item['place_id'] for item in body['schools']], ['p'])
        self.assertEqual(sleeps, [finder.PAGE_TOKEN_DELAY_SECONDS])

    def test_search_runs_in_parallel_and_bounded(self):
        import threading
        import time as real_time
        active, peak, lock = [0], [0], threading.Lock()

        def fake_get(url, params=None, timeout=None):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            real_time.sleep(0.05)
            with lock:
                active[0] -= 1
            return reply({'results': []})
        with patch.object(service.requests, 'get', side_effect=fake_get):
            self.search(address='Fairfax', keywords=['a', 'b', 'c', 'd', 'e', 'f'], types=['school', 'preschool'])
        self.assertGreater(peak[0], 1)
        self.assertLessEqual(peak[0], finder.SEARCH_WORKERS)

    def test_route_plan_still_accepts_finder_results(self):
        schools = [{'place_id': 'a', 'lat': 38.9, 'lng': -77.2}, {'place_id': 'b', 'lat': 38.8, 'lng': -77.3}]
        response = self.client.post('/api/route-plan', headers=self.auth(self.john),
                                    json={'schools': schools, 'start_address': 'Fairfax'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()['route']), 2)


class DetailsTests(FinderBase):
    def details(self, ids, user=None):
        return self.client.post('/api/find-schools/details', headers=self.auth(user or self.john), json={'place_ids': ids})

    def test_returns_details_and_caches(self):
        result = {'status': 'OK', 'result': {
            'formatted_phone_number': '(703) 555-0100', 'website': 'https://oak.example.test',
            'formatted_address': '1 Main St, Fairfax, VA',
            'opening_hours': {'weekday_text': ['Monday: 8-5', 'Tuesday: 8-5']}}}
        with patch.object(service.requests, 'get', return_value=reply(result)) as get:
            body = self.details(['abc', 'def']).get_json()
            self.assertEqual(get.call_count, 2)
            self.assertEqual(body['details']['abc'], {
                'phone': '(703) 555-0100', 'website': 'https://oak.example.test',
                'hours_text': 'Monday: 8-5; Tuesday: 8-5', 'formatted_address': '1 Main St, Fairfax, VA'})
            self.details(['abc'])
            self.assertEqual(get.call_count, 2)  # served from the cache
        with patch.object(service.requests, 'get', return_value=reply({'status': 'OK', 'result': {}})):
            sparse = self.details(['ghi']).get_json()['details']['ghi']
        self.assertEqual(sparse, {'phone': None, 'website': None, 'hours_text': None, 'formatted_address': None})

    def test_validation_and_failures(self):
        self.assertEqual(self.details([]).status_code, 400)
        self.assertEqual(self.details([f'id{i}' for i in range(21)]).status_code, 400)
        self.assertEqual(self.details(['bad id!']).status_code, 400)
        self.assertEqual(self.details([5]).status_code, 400)
        self.assertEqual(self.client.post('/api/find-schools/details', json={'place_ids': ['a']}).status_code, 401)
        with patch.object(service.requests, 'get', return_value=reply({'status': 'NOT_FOUND'})):
            self.assertEqual(self.details(['zzz']).status_code, 502)
        self.assertNotIn('zzz', finder._details_cache)

    def test_one_failed_place_does_not_block_the_others(self):
        def fake_get(url, params=None, timeout=None):
            if params['place_id'] == 'bad':
                return reply({'status': 'NOT_FOUND'})
            return reply({'status': 'OK', 'result': {'website': 'https://x.example.test'}})
        with patch.object(service.requests, 'get', side_effect=fake_get):
            body = self.details(['good', 'bad']).get_json()
        self.assertEqual(list(body['details']), ['good'])


class SaveBatchTests(FinderBase):
    def save(self, schools, user=None, **extra):
        return self.client.post('/api/find-schools/save-batch', headers=self.auth(user or self.john),
                                json={'schools': schools, **extra})

    def test_creates_blank_email_schools_and_skips_duplicates_with_owner(self):
        existing = service.SalesSchool(school_name='Taken School', email='', user_id=self.mary.id,
                                       place_id='taken', address='4 Elm St, Fairfax')
        service.db.session.add(existing)
        service.db.session.commit()
        response = self.save([
            {'place_id': 'new-1', 'school_name': 'New One', 'address': '1 A St', 'lat': 38.9, 'lng': -77.1,
             'phone': '555', 'website': 'https://one.example.test', 'school_type': 'elementary'},
            {'place_id': 'taken', 'school_name': 'Whatever', 'address': 'x'},
            {'place_id': 'new-2', 'school_name': 'Taken School', 'address': '4 Elm St, Fairfax, VA 22030'},
            {'place_id': 'new-1', 'school_name': 'New One Again'},
            {'place_id': 'new-3', 'school_name': 'With Email', 'email': 'hello@example.test'},
        ])
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item['place_id'] for item in body['created']], ['new-1', 'new-3'])
        self.assertEqual([(s['place_id'], s['reason']) for s in body['skipped']],
                         [('taken', 'duplicate'), ('new-2', 'duplicate'), ('new-1', 'duplicate')])
        self.assertEqual(body['skipped'][0]['owner_name'], 'Mary')
        self.assertIn('Mary', body['skipped'][0]['detail'])
        self.assertEqual(body['skipped'][0]['existing_id'], existing.id)
        row = service.db.session.get(service.SalesSchool, body['created'][0]['id'])
        self.assertEqual((row.email, row.user_id, row.status, row.school_type, row.lat, row.place_id),
                         ('', self.john.id, 'pending', 'elementary', 38.9, 'new-1'))
        self.assertEqual((row.phone, row.website), ('555', 'https://one.example.test'))
        self.assertEqual(service.SalesSchool.query.count(), 3)

    def test_email_conflict_is_a_duplicate(self):
        service.db.session.add(service.SalesSchool(school_name='Owned', email='dir@example.test', user_id=self.mary.id))
        service.db.session.commit()
        body = self.save([{'place_id': 'e1', 'school_name': 'Other Name', 'email': 'DIR@example.test'}]).get_json()
        self.assertEqual(body['created'], [])
        self.assertEqual(body['skipped'][0]['reason'], 'duplicate')

    def test_assign_to_is_admin_only(self):
        denied = self.save([{'place_id': 'a1', 'school_name': 'A'}], assign_to=self.mary.id)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(service.SalesSchool.query.count(), 0)
        self.assertEqual(self.save([{'place_id': 'a1', 'school_name': 'A'}], assign_to=self.john.id).status_code, 200)
        body = self.save([{'place_id': 'a2', 'school_name': 'B'}], user=self.admin, assign_to=self.mary.id).get_json()
        row = service.db.session.get(service.SalesSchool, body['created'][0]['id'])
        self.assertEqual(row.user_id, self.mary.id)
        self.assertEqual(self.save([{'place_id': 'a3', 'school_name': 'C'}], user=self.admin, assign_to=9999).status_code, 400)

    def test_invalid_entries_are_skipped_not_fatal(self):
        body = self.save([
            {'place_id': 'v1', 'school_name': ''}, {'school_name': 'No Id'}, 'junk',
            {'place_id': 'v2', 'school_name': 'Bad Type', 'school_type': 'college'},
            {'place_id': 'v3', 'school_name': 'Bad Coords', 'lat': 500, 'lng': 0},
            {'place_id': 'v4', 'school_name': 'Bad Email', 'email': 'nope'},
            {'place_id': 'v5', 'school_name': 'Good'},
        ]).get_json()
        self.assertEqual([item['place_id'] for item in body['created']], ['v5'])
        self.assertEqual(len(body['skipped']), 6)
        self.assertTrue(all(item['reason'] == 'invalid' for item in body['skipped']))

    def test_batch_size_validation_and_auth(self):
        self.assertEqual(self.save([]).status_code, 400)
        self.assertEqual(self.save([{'place_id': str(i), 'school_name': 'S'} for i in range(51)]).status_code, 400)
        self.assertEqual(self.client.post('/api/find-schools/save-batch', json={'schools': []}).status_code, 401)

    def test_blank_email_schools_can_never_be_looked_up_by_email(self):
        self.save([{'place_id': 'b1', 'school_name': 'Phone Only'}, {'place_id': 'b2', 'school_name': 'Also Phone Only'}])
        self.assertEqual(service.SalesSchool.query.count(), 2)  # two blank emails do not collide


if __name__ == '__main__':
    unittest.main()
