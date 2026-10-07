"""The Finder loads partner names per request without blocking API startup."""

import base64
import os
import unittest
from unittest.mock import Mock, patch

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET_KEY'] = 'local-test-key'
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())

from api import api as service  # noqa: E402


class SchoolFinderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        service.app.config['TESTING'] = True
        with service.app.app_context():
            token = service.create_access_token(identity='1')
        cls.headers = {'Authorization': f'Bearer {token}'}
        cls.client = service.app.test_client()

    def test_finder_loads_partner_groups_and_filters_results(self):
        places = [
            {'place_id': 'known', 'name': 'PSA Academy', 'vicinity': 'Fairfax',
             'geometry': {'location': {'lat': 38.8, 'lng': -77.3}}},
            {'place_id': 'new', 'name': 'Oak School', 'vicinity': 'Fairfax',
             'geometry': {'location': {'lat': 38.9, 'lng': -77.2}}},
        ]
        with (patch.object(service, 'load_PSA_school_sheet', return_value=[['sheet']]) as load,
              patch.object(service, 'split_sheet_schools', return_value=(
                  [{'name': 'PSA Academy'}], [], [])) as split,
              patch.object(service, 'geocode_address', return_value=(38.8, -77.3)),
              patch.object(service.requests, 'get', return_value=Mock(
                  **{'json.return_value': {'results': places}}))):
            response = self.client.post('/api/find-schools', headers=self.headers,
                                        json={'address': 'Fairfax', 'keywords': ['preschool']})

        self.assertEqual(response.status_code, 200)
        self.assertEqual([item['place_id'] for item in response.get_json()['schools']], ['new'])
        load.assert_called_once_with()
        split.assert_called_once_with([['sheet']])

    def test_sheet_failure_returns_clear_error(self):
        with (patch.object(service, 'load_PSA_school_sheet', side_effect=RuntimeError('offline')),
              patch.object(service, 'geocode_address') as geocode,
              patch.object(service.app.logger, 'exception')):
            response = self.client.post('/api/find-schools', headers=self.headers,
                                        json={'address': 'Fairfax', 'keywords': ['preschool']})

        self.assertEqual(response.status_code, 503)
        self.assertIn('temporarily unavailable', response.get_json()['error'])
        geocode.assert_not_called()


if __name__ == '__main__':
    unittest.main()
