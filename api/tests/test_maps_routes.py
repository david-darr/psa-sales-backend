"""Persistent map state, provider caching, and bounded visit suggestions."""
import base64
import os
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch
import requests

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
from api import api as service
from api.routing import order_visits


class MapRouteTests(unittest.TestCase):
    def setUp(self):
        self.context = service.app.app_context()
        self.context.push()
        service.app.config['TESTING'] = True
        service.db.create_all()
        self.admin = service.User(name='Admin', email='admin@example.test', admin=True, password_hash='unused')
        self.staff = service.User(name='Staff', email='staff@example.test', admin=False, password_hash='unused')
        service.db.session.add_all([self.admin, self.staff])
        service.db.session.commit()
        self.headers = {'Authorization': 'Bearer ' + service.create_access_token(identity=str(self.admin.id))}
        self.staff_headers = {'Authorization': 'Bearer ' + service.create_access_token(identity=str(self.staff.id))}
        self.client = service.app.test_client()

    def tearDown(self):
        service.db.session.remove()
        service.db.drop_all()
        self.context.pop()

    def test_geocoding_reuses_saved_coordinates_and_retains_them_on_outage(self):
        provider = Mock()
        provider.json.return_value = {'items': [{'position': {'lat': 38.9, 'lng': -77.2}}]}
        with patch.object(service.requests, 'get', return_value=provider) as get:
            self.assertEqual(service.geocode_address('123 Maple St'), (38.9, -77.2))
            self.assertEqual(service.geocode_address(' 123 MAPLE St. '), (38.9, -77.2))
            self.assertEqual(get.call_count, 1)
        cached = service.GeocodedAddress.query.one()
        cached.checked_at = service.utc_now() - timedelta(days=181)
        service.db.session.commit()
        with patch.object(service.requests, 'get', side_effect=requests.Timeout()):
            self.assertEqual(service.geocode_address('123 Maple St'), (38.9, -77.2))

    def test_map_refresh_is_bounded_and_snapshot_survives_a_new_session(self):
        points = [{'name': f'School {index}', 'address': f'{index} Test Lane'} for index in range(12)]
        def fake_geocode(address):
            service.db.session.add(service.GeocodedAddress(address_key=service.normalize_name(address), lat=38.9, lng=-77.2))
            service.db.session.commit()
            return 38.9, -77.2
        with (patch.object(service, 'load_PSA_school_sheet', return_value=[]),
              patch.object(service, 'split_sheet_schools', return_value=(points, [], [])),
              patch.object(service, 'geocode_address', side_effect=fake_geocode) as geocode):
            self.assertEqual(self.client.post('/api/refresh-map-schools', headers=self.staff_headers).status_code, 403)
            first = self.client.post('/api/refresh-map-schools', headers=self.headers).get_json()
            self.assertEqual(first['processed'], 10)
            self.assertEqual(first['remaining'], 4)
            service.db.session.remove()
            snapshot = self.client.get('/api/map-schools', headers=self.headers).get_json()
            self.assertEqual(sum(map(len, snapshot.values())), 10)
            second = self.client.post('/api/refresh-map-schools', headers=self.headers).get_json()
            self.assertEqual(second['remaining'], 0)
            self.assertEqual(second['mapped'], 14)
            self.assertEqual(geocode.call_count, 14)

    def test_visit_order_handles_25_unique_stops(self):
        stops = [{'place_id': str(index), 'lat': index % 5, 'lng': index // 5} for index in range(25)]
        route, distance = order_visits(stops, (-1, -1), lambda a, b, c, d: ((a-c)**2 + (b-d)**2)**.5)
        self.assertEqual(set(route), {item['place_id'] for item in stops})
        self.assertEqual(len(route), 25)
        self.assertGreater(distance, 0)

    def test_route_rejects_unbounded_or_invalid_input_before_provider_calls(self):
        stops = [{'place_id': str(index), 'lat': 38.9, 'lng': -77.2} for index in range(26)]
        with patch.object(service, 'geocode_address') as geocode:
            for sample in (stops, [stops[0], stops[0]], [stops[0], {'place_id': 'bad', 'lat': 100, 'lng': 0}]):
                result = self.client.post('/api/route-plan', headers=self.headers,
                    json={'schools': sample, 'start_address': 'Fairfax'})
                self.assertEqual(result.status_code, 400)
            geocode.assert_not_called()


if __name__ == '__main__':
    unittest.main()
