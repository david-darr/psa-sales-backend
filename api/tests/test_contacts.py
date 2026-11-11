import csv
import io
from datetime import timedelta
from unittest.mock import patch

from api.tests.test_admin_sales import AdminSalesBase
from api import api as service
from api.contacts import now


class ContactsTests(AdminSalesBase):
    def listing(self, school=None, user=None):
        return self.client.get(f'/api/sales-schools/{(school or self.open_school).id}/contacts', headers=self.auth(user or self.john))

    def preview(self, rows, user=None):
        buffer = io.StringIO()
        fields = list(dict.fromkeys(key for row in rows for key in row))
        writer = csv.DictWriter(buffer, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
        return self.client.post('/api/contact-imports/preview', data={'file': (io.BytesIO(buffer.getvalue().encode()), 'schools.csv')}, headers=self.auth(user or self.john))

    def commit(self, preview, user=None, **data):
        return self.client.post('/api/contact-imports/' + preview['id'] + '/commit', json={'file_hash': preview['file_hash'], **data}, headers=self.auth(user or self.john))

    def test_backfill_hook_and_legacy_edits_preserve_roles(self):
        row = self.listing().get_json()['contacts'][0]
        self.assertEqual(row['roles'], ['unknown'])
        response = self.client.patch(f"/api/sales-schools/{self.open_school.id}/contacts/{row['id']}", json={
            'version': row['version'], 'contact_version': row['contact_version'], 'name': 'Alex', 'roles': ['principal_ap']}, headers=self.auth(self.john))
        self.assertEqual(response.status_code, 200, response.get_json())
        self.open_school.set_additional_emails(['Pta@example.test'])
        service.db.session.commit()
        contacts = self.listing().get_json()['contacts']
        self.assertEqual(contacts[0]['roles'], ['principal_ap'])
        self.assertEqual(contacts[1]['email'], 'pta@example.test')
        self.assertEqual(self.open_school.contact_name, 'Alex')

    def test_shared_mailbox_suppression_privacy_and_stale_edit(self):
        shared = self.school('Sister Primary', self.mary, 'pending')
        shared.email = self.open_school.email
        service.db.session.commit()
        row = self.listing().get_json()['contacts'][0]
        self.assertEqual(row['linked_school_count'], 2)
        self.assertEqual(len(row['shared_schools']), 1)
        url = f"/api/sales-schools/{self.open_school.id}/contacts/{row['id']}"
        body = dict(version=row['version'], contact_version=row['contact_version'], do_not_contact=True, suppression_reason='Requested no outreach')
        self.assertEqual(self.client.patch(url, json=body, headers=self.auth(self.john)).status_code, 200)
        self.assertEqual(self.client.patch(url, json=body, headers=self.auth(self.john)).status_code, 409)
        other = self.listing(shared, self.mary).get_json()['contacts'][0]
        self.assertTrue(other['do_not_contact'])
        other.update(do_not_contact=False)
        payload = {key: other[key] for key in ('version', 'contact_version', 'do_not_contact')}
        payload['suppression_reason'] = 'Asked to restart'
        other_url = f"/api/sales-schools/{shared.id}/contacts/{other['id']}"
        self.assertEqual(self.client.patch(other_url, json=payload, headers=self.auth(self.mary)).status_code, 403)
        self.assertEqual(self.client.patch(other_url, json=payload, headers=self.auth(self.admin)).status_code, 200)
        self.assertEqual(self.listing(self.open_school, self.mary).status_code, 404)

    def test_dnc_blocks_smtp_before_connecting(self):
        contact = service.Contact.query.filter_by(email=self.open_school.email).one()
        contact.do_not_contact = True; service.db.session.commit()
        with patch.object(service.SmtpSender, '_build_and_send') as send:
            sender = service.SmtpSender('a@example.test', 'password', 'A')
            with self.assertRaisesRegex(ValueError, 'do not contact'):
                sender.send({'to_email': contact.email, 'pdf_files': []})
            send.assert_not_called()

    def test_preview_no_school_writes_and_import_keeps_all_roles(self):
        before = service.SalesSchool.query.count(), service.Contact.query.count()
        rows = [dict(school_name='Cedar Community', address='1 Pine St', email='principal@example.test', contact_role='principal', county='Loudoun', stage='pending'),
                dict(school_name='Cedar Community', address='1 Pine St', email='pta@example.test', contact_role='pta', county='Loudoun', stage='pending')]
        response = self.preview(rows)
        self.assertEqual(response.status_code, 200, response.get_json())
        plan = response.get_json()
        self.assertEqual((service.SalesSchool.query.count(), service.Contact.query.count()), before)
        self.assertEqual(len(plan['groups']), 1)
        result = self.commit(plan)
        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertEqual(result.get_json()['contacts_added'], 2)
        self.assertEqual(self.commit(plan).get_json(), result.get_json())
        school = service.SalesSchool.query.filter_by(school_name='Cedar Community').one()
        self.assertEqual(school.county, 'Loudoun')
        self.assertEqual(set(school.get_all_emails()), {'principal@example.test', 'pta@example.test'})
        roles = [link.roles_json for link in service.SchoolContact.query.filter_by(school_id=school.id)]
        self.assertTrue(any('principal_ap' in value for value in roles))
        self.assertTrue(any('pta_pto' in value for value in roles))

    def test_existing_school_add_contact_preserves_owner_stage_notes_and_dnc(self):
        self.open_school.notes = 'Preserve me'
        self.open_school.status = 'replied'
        contact = service.Contact(email='shared@example.test', do_not_contact=True, suppression_reason='No marketing')
        service.db.session.add(contact); service.db.session.commit()
        plan = self.preview([dict(school_name=self.open_school.school_name, email=contact.email, stage='pending', notes='Replace me', contact_role='pta')]).get_json()
        response = self.commit(plan)
        self.assertEqual(response.status_code, 200, response.get_json())
        service.db.session.refresh(self.open_school)
        self.assertEqual((self.open_school.status, self.open_school.notes, self.open_school.user_id), ('replied', 'Preserve me', self.john.id))
        self.assertTrue(service.db.session.get(service.Contact, contact.id).do_not_contact)
        self.assertIn('shared@example.test', self.open_school.get_all_emails())

    def test_candidates_cross_rep_and_expired_snapshots(self):
        plan = self.preview([dict(school_name='Beta Academy', email='fresh@example.test')], self.mary).get_json()
        self.assertEqual(plan['groups'][0]['action'], 'conflict')
        self.assertEqual(self.commit(plan, self.mary).status_code, 400)
        denied = self.commit(plan, self.mary, decisions={plan['groups'][0]['key']: {'action': 'existing', 'school_id': self.won.id}})
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.commit(plan, self.john).status_code, 404)
        other = self.preview([dict(school_name='New Valley', email='ok@example.test')]).get_json()
        preview = service.db.session.get(service.ContactImport, other['id'])
        preview.expires_at = now() - timedelta(seconds=1); service.db.session.commit()
        self.assertEqual(self.commit(other).status_code, 409)

    def test_fuzzy_in_file_duplicate_invalid_rows_and_stale_data(self):
        rows = [dict(school_name='Mountain View Elementary School', email='a@example.test'),
                dict(school_name='Mountain View Elementary School (Purcellville)', email='b@example.test'),
                dict(school_name='Bad Row', email='bad', contact_role='unrecognized')]
        plan = self.preview(rows).get_json()
        self.assertEqual(len(plan['errors']), 1)
        self.assertEqual(plan['groups'][1]['action'], 'conflict')
        self.assertEqual(self.commit(plan).status_code, 400)
        self.open_school.notes = 'Changed while reviewing'; service.db.session.commit()
        self.assertEqual(self.commit(plan, skip_invalid=True).status_code, 409)

    def test_shared_pta_links_not_duplicate_schools(self):
        rows = [dict(school_name='Kings Park', address='1 North Ave', email='joint@example.test', contact_role='pta'),
                dict(school_name='Kings Glen', address='2 South Ave', email='joint@example.test', contact_role='pta')]
        plan = self.preview(rows).get_json()
        response = self.commit(plan)
        self.assertEqual(response.status_code, 200, response.get_json())
        contact = service.Contact.query.filter_by(email='joint@example.test').one()
        self.assertEqual(service.SchoolContact.query.filter_by(contact_id=contact.id).count(), 2)
        self.assertEqual(response.get_json()['schools_added'], 2)

    def test_heavy_synthetic_csv_145_schools_410_contacts(self):
        rows = [dict(school_name=f'Campus {i:03d} District {i * 1237}', address=f'{i} School Lane', email=f'c{n}@example.test', contact_role='pta' if n % 2 else 'principal') for n in range(410) for i in [n % 145]]
        plan = self.preview(rows).get_json()
        decisions = {g['key']: {'action': 'new'} for g in plan['groups'] if g['action'] == 'conflict'}
        response = self.commit(plan, decisions=decisions)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['schools_added'], 145)
        self.assertEqual(response.get_json()['contacts_added'], 410)

    def test_manual_shared_confirmation_and_legacy_projection_edits(self):
        shared = dict(school_name='Different Sister Campus', email=self.open_school.email, address='900 Different Way')
        self.assertEqual(self.client.post('/api/add-school', json=shared, headers=self.auth(self.john)).status_code, 409)
        shared['shared_contact_confirmed'] = True
        created = self.client.post('/api/add-school', json=shared, headers=self.auth(self.john))
        self.assertEqual(created.status_code, 201, created.get_json())
        sid = created.get_json()['id']
        changed = self.client.patch(f'/api/sales-schools/{sid}', json={'county': 'Loudoun', 'contact_name': 'Pat', 'additional_emails': ['extra@example.test']}, headers=self.auth(self.john))
        self.assertEqual(changed.status_code, 200, changed.get_json())
        self.assertEqual(changed.get_json()['county'], 'Loudoun')
        rows = self.client.get(f'/api/sales-schools/{sid}/contacts', headers=self.auth(self.john)).get_json()['contacts']
        self.assertEqual(rows[0]['name'], 'Pat')
        self.assertEqual(len(rows), 2)
        changed = self.client.patch(f'/api/sales-schools/{sid}', json={'additional_emails': []}, headers=self.auth(self.john))
        self.assertEqual(changed.status_code, 200)
        rows = self.client.get(f'/api/sales-schools/{sid}/contacts', headers=self.auth(self.john)).get_json()['contacts']
        self.assertEqual(len(rows), 1)

    def test_create_suppressed_contact_and_invalid_payloads(self):
        url = f'/api/sales-schools/{self.open_school.id}/contacts'
        for body in ({'email': 'a@example.test', 'roles': {}}, {'email': 'bad'},
                     {'email': 'a@example.test', 'do_not_contact': True}, {'email': 'a@example.test', 'is_primary': 'yes'}):
            self.assertEqual(self.client.post(url, json=body, headers=self.auth(self.john)).status_code, 400, body)
        created = self.client.post(url, json={'email':'new-dnc@example.test','do_not_contact':True,'suppression_reason':'Explicit request'}, headers=self.auth(self.john))
        self.assertEqual(created.status_code, 201, created.get_json())
        self.assertTrue(created.get_json()['do_not_contact'])
        self.assertEqual(self.client.get(url).status_code, 401)
        with patch('api.api.open_smtp_connection') as connect:
            self.assertFalse(service.send_email_with_attachments('a@example.test','pw','new-dnc@example.test','Hello','Body',[],'A'))
            connect.assert_not_called()

    def test_exact_match_cannot_be_forced_new_and_invalid_skips_are_explicit(self):
        plan = self.preview([dict(school_name='Alpha Prep', email='new@example.test')]).get_json()
        self.assertEqual(self.commit(plan, decisions={plan['groups'][0]['key']: {'action':'new'}}).status_code, 400)
        bad = self.preview([dict(school_name='Pine Grove',email='ok@example.test'),dict(school_name='Bad',email='not-an-email')]).get_json()
        self.assertEqual(self.commit(bad).status_code, 400)
        result = self.commit(bad, skip_invalid=True)
        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertEqual(result.get_json()['rows_skipped'], 1)

    def test_school_only_stop_preserves_shared_contact_and_other_school(self):
        shared=self.school('Shared PTA sister school',self.mary,'pending')
        shared.email=self.open_school.email;service.db.session.commit()
        first=self.listing().get_json()['contacts'][0]
        other=self.listing(shared,self.mary).get_json()['contacts'][0]
        url=f"/api/sales-schools/{self.open_school.id}/contacts/{first['id']}"
        response=self.client.patch(url,headers=self.auth(self.john),json=dict(version=first['version'],contact_version=first['contact_version'],school_do_not_contact=True,school_suppression_reason='School asked to pause'))
        self.assertEqual(response.status_code,200,response.get_json())
        result=response.get_json()
        self.assertTrue(result['school_do_not_contact']);self.assertTrue(result['effective_do_not_contact'])
        self.assertFalse(result['do_not_contact'])
        self.assertEqual(result['contact_version'],first['contact_version'])
        unchanged=self.listing(shared,self.mary).get_json()['contacts'][0]
        self.assertEqual(unchanged,other)
        self.assertTrue(service.contact_is_blocked(shared.email,school_id=self.open_school.id))
        self.assertFalse(service.contact_is_blocked(shared.email,school_id=shared.id))
        self.assertFalse(service.contact_is_blocked(shared.email))
        with patch.object(service.SmtpSender,'_build_and_send') as send:
            sender=service.SmtpSender('sender@example.test','fake','Test')
            with self.assertRaises(ValueError):sender.send(dict(to_email=shared.email,school_id=self.open_school.id,pdf_files=[]))
            sender.send(dict(to_email=shared.email,school_id=shared.id,pdf_files=[]))
            self.assertEqual(send.call_count,1)
        response=self.client.patch(url,headers=self.auth(self.john),json=dict(version=result['version'],contact_version=result['contact_version'],school_do_not_contact=False,school_suppression_reason='School requested restart'))
        self.assertEqual(response.status_code,200)
        contact=service.db.session.get(service.Contact,result['contact_id']);contact.do_not_contact=True;service.db.session.commit()
        self.assertTrue(service.contact_is_blocked(shared.email,school_id=shared.id))
        self.assertTrue(service.contact_is_blocked(shared.email,school_id=self.open_school.id))

    def test_school_stop_requires_reason_and_remains_owner_scoped(self):
        row=self.listing().get_json()['contacts'][0]
        url=f"/api/sales-schools/{self.open_school.id}/contacts/{row['id']}"
        body=dict(version=row['version'],contact_version=row['contact_version'],school_do_not_contact=True)
        self.assertEqual(self.client.patch(url,headers=self.auth(self.john),json=body).status_code,400)
        body['school_suppression_reason']='Asked to stop'
        self.assertEqual(self.client.patch(url,headers=self.auth(self.mary),json=body).status_code,404)
