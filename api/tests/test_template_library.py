import json
from unittest.mock import patch
from api.tests.test_outreach_batches import OutreachBase
from api import api as service, outreach
from api.template_library import render_copy, validate_copy


class TemplateLibraryTests(OutreachBase):
    def template(self, **changes):
        body = dict(name='Principal intro', kind='initial', step=0, audience='principal_ap',
                    subject='For {school name}', body='Hello {contact name}, from {my name}, {my email}')
        body.update(changes)
        response = self.client.post('/api/outreach/templates', headers=self.auth(self.admin), json=body)
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()

    def payload(self, school, template, **changes):
        return dict(school_ids=[school.id], kind=template['kind'], template_id=template['id'],
                    template_revision=template['revision'], **changes)

    def preview(self, payload, user=None):
        return self.client.post('/api/email-preview', headers=self.auth(user or self.owner), json=payload)

    def edit(self, template, **changes):
        return self.client.put(f"/api/outreach/templates/{template['id']}", headers=self.auth(self.admin), json={**template, **changes})

    def test_permissions_and_private_versions(self):
        self.assertEqual(self.client.get('/api/outreach/templates').status_code, 401)
        self.assertEqual(self.client.post('/api/outreach/templates', headers=self.auth(self.owner), json={}).status_code, 403)
        self.assertEqual(self.client.post('/api/outreach/templates/seed-winter-2027', headers=self.auth(self.owner), json={}).status_code, 403)
        template = self.template()
        self.assertEqual(len(self.client.get('/api/outreach/templates', headers=self.auth(self.owner)).get_json()['items']), 1)
        self.assertEqual(self.client.get(f"/api/outreach/templates/{template['id']}/versions", headers=self.auth(self.owner)).status_code, 403)
        self.assertEqual(self.client.put(f"/api/outreach/templates/{template['id']}", headers=self.auth(self.owner), json=template).status_code, 403)

    def test_seed_exact_copy_idempotent_and_preserves_edits(self):
        from api.template_library import SEED
        endpoint = '/api/outreach/templates/seed-winter-2027'
        self.assertEqual(self.client.post(endpoint, headers=self.auth(self.admin)).get_json()['added'], 16)
        items = self.client.get('/api/outreach/templates', headers=self.auth(self.owner)).get_json()['items']
        source = json.loads(SEED.read_text(encoding='utf-8'))['templates']
        self.assertEqual([(t['subject'], t['body']) for t in items], [(t['subject'], t['body']) for t in source])
        self.assertEqual(len([t for t in items if t['step'] == 3]), 4)
        self.assertTrue(all(t['attachments'] == [] for t in items))
        self.assertEqual(self.edit(items[0], name='Admin changed this').status_code, 200)
        self.assertEqual(self.client.post(endpoint, headers=self.auth(self.admin)).get_json()['added'], 0)
        self.assertEqual(service.MailTemplate.query.count(), 16)
        version = service.MailTemplateVersion.query.filter_by(template_id=items[0]['id'], revision=2).one()
        self.assertEqual(json.loads(version.snapshot)['name'], 'Admin changed this')

    def test_revision_conflict_history_archive_and_restore(self):
        template = self.template()
        edited = self.edit(template, archived=True).get_json()
        self.assertEqual(edited['revision'], 2)
        self.assertEqual(self.edit(template).status_code, 409)
        self.assertEqual(self.client.get('/api/outreach/templates', headers=self.auth(self.owner)).get_json()['items'], [])
        self.assertEqual(len(self.client.get('/api/outreach/templates?include_archived=1', headers=self.auth(self.admin)).get_json()['items']), 1)
        history = self.client.get(f"/api/outreach/templates/{template['id']}/versions", headers=self.auth(self.admin)).get_json()['items']
        self.assertEqual([v['revision'] for v in history], [2, 1])
        self.assertEqual(self.edit(edited, archived=False).get_json()['revision'], 3)

    def test_unknown_and_malformed_fields_and_missing_used_value(self):
        for subject in ('For {school nam}', 'For {school name', 'For [typo1]', 'Bad\nHeader'):
            with self.assertRaises(ValueError): validate_copy(subject, 'Hi')
        school = self.school('No Contact', contact='')
        template = self.template()
        response = self.preview(self.payload(school, template))
        self.assertEqual(response.status_code, 400)
        self.assertIn('Missing contact name', response.get_json()['error'])
        self.assertEqual(self.preview(self.payload(school, template, body='Hello {school name}')).status_code, 200)

    def test_square_aliases_and_curly_fields_render_and_html_escape(self):
        school = self.school('School & Co', contact='<Director>')
        template = self.template()
        response = self.preview(self.payload(school, template, body='Hi [contact_name] from {my name}')).get_json()
        self.assertEqual(response['previews'][0]['body_text'], 'Hi <Director> from Owner')
        self.assertIn('&lt;Director&gt;', response['previews'][0]['body_html'])
        self.assertEqual(response['previews'][0]['attachments'], [])

    def test_review_required_and_no_worker_on_failure(self):
        school, template = self.school('Safe School'), self.template()
        response = self.create_batch(self.owner, **self.payload(school, template))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.started, [])
        self.assertEqual(outreach.OutreachBatch.query.count(), 0)

    def test_batch_copy_frozen_and_new_version_does_not_change_queue(self):
        school, template = self.school('Frozen School'), self.template()
        payload = self.payload(school, template, subject='Reviewed {school name}', body='Batch copy from {my name}')
        preview = self.preview(payload).get_json()
        response = self.create_batch(self.owner, **payload, preview_token=preview['preview_token'])
        self.assertEqual(response.status_code, 202, response.get_json())
        recipient = outreach.OutreachRecipient.query.one()
        self.assertEqual(recipient.body, 'Batch copy from Owner')
        self.assertEqual(recipient.attachments, '[]')
        self.assertEqual(self.edit(template, body='New library text').status_code, 200)
        batch = outreach.OutreachBatch.query.one()
        self.assertEqual(json.loads(batch.template_snapshot)['body'], template['body'])
        self.assertEqual(service.MailTemplateVersion.query.filter_by(template_id=template['id'], revision=1).one().snapshot.count('New library text'), 0)
        self.run_workers()
        self.assertEqual(self.get_batch(self.owner, batch.id)['sent'], 1)
        self.assertEqual(service.db.session.get(outreach.OutreachRecipient, recipient.id).body, 'Batch copy from Owner')

    def test_changes_after_preview_require_review_again(self):
        school, template = self.school('Changing School'), self.template()
        payload = self.payload(school, template)
        token = self.preview(payload).get_json()['preview_token']
        for changes in ({'body': 'Changed body'}, {'subject': 'Changed subject'}):
            self.assertEqual(self.create_batch(self.owner, **{**payload, **changes}, preview_token=token).status_code, 409)
        school.contact_name = 'Different person'; service.db.session.commit()
        self.assertEqual(self.create_batch(self.owner, **payload, preview_token=token).status_code, 409)
        edited = self.edit(template, subject='Library update').get_json()
        self.assertEqual(self.preview(payload).status_code, 400)
        payload['template_revision'] = edited['revision']
        self.assertEqual(self.create_batch(self.owner, **payload, preview_token=token).status_code, 409)
        self.edit(edited, archived=True)
        self.assertEqual(self.preview(payload).status_code, 400)

    def test_preview_is_bound_to_sender(self):
        school, template = self.school('Transfer School'), self.template()
        payload = self.payload(school, template)
        token = self.preview(payload).get_json()['preview_token']
        school.user_id = self.other.id; service.db.session.commit()
        self.assertEqual(self.create_batch(self.other, **payload, preview_token=token).status_code, 409)

    def test_followup_step_type_and_no_attachments(self):
        school = self.school('Follow School', status='contacted')
        self.sent_email(school, 8)
        self.sync_ready(self.owner)
        template = self.template(kind='followup', step=2)
        payload = self.payload(school, template)
        self.assertEqual(self.preview(payload).status_code, 400)
        template = self.edit(template, step=1).get_json()
        payload = self.payload(school, template)
        self.assertEqual(self.preview(payload).status_code, 200)
        self.assertEqual(self.preview({**payload, 'kind': 'initial'}).status_code, 400)
        self.assertEqual(self.preview({**payload, 'attachments': True}).status_code, 400)
        self.assertEqual(service.FOLLOWUP_SCHEDULE_DAYS, (3, 7))

    def test_shared_batches_cannot_bypass_full_review_limit(self):
        template = self.template()
        payload = dict(school_ids=list(range(1, 102)), kind='initial', template_id=template['id'], template_revision=1)
        self.assertEqual(self.create_batch(self.owner, **payload).status_code, 400)
        self.assertEqual(outreach.OutreachBatch.query.count(), 0)

    def test_bad_metadata_and_batch_copy_fields_rejected(self):
        school, template = self.school('Bad Fields'), self.template()
        payload = self.payload(school, template)
        for change in ({'template_id': True}, {'template_revision': '1'}, {'body': 'Hi {unknown}'}, {'attachments': True}):
            self.assertEqual(self.preview({**payload, **change}).status_code, 400)
        self.assertEqual(self.client.post('/api/outreach/templates', headers=self.auth(self.admin), json=[]).status_code, 400)

    def test_attachment_bytes_are_frozen_for_review_queue_and_mime(self):
        import tempfile
        from pathlib import Path
        from api import template_library
        with tempfile.TemporaryDirectory() as directory:
            filename = 'PSA After School.pdf'
            path = Path(directory) / filename
            original = b'%PDF-1.4\nOriginal immutable flyer'
            path.write_bytes(original)
            with patch.object(template_library, 'PDF_DIRECTORY', Path(directory)):
                template = self.template(attachment_file=filename)
                self.assertEqual(template['attachments'][0]['name'], filename)
                school = self.school('Flyer School')
                payload = self.payload(school, template)
                review = self.preview(payload).get_json()
                self.assertEqual(review['previews'][0]['attachments'], [filename])
                queued = self.create_batch(self.owner, **payload, preview_token=review['preview_token'])
                self.assertEqual(queued.status_code, 202)
                recipient = outreach.OutreachRecipient.query.one()
                frozen_files = json.loads(recipient.attachments)
                path.write_bytes(b'%PDF-1.4\nReplaced source flyer')
                newer = self.edit(template, attachment_file=filename, attachment_ids=[]).get_json()
                self.assertNotEqual(newer['attachment_id'], template['attachment_id'])
                message = service.build_email_message(self.owner.email, self.owner.name, school.email,
                    recipient.subject, recipient.body, frozen_files)
                files = [part for part in message.walk() if part.get_content_disposition() == 'attachment']
                self.assertEqual(len(files), 1)
                self.assertEqual(files[0].get_payload(decode=True), original)
                self.assertEqual(files[0].get_filename(), filename)
                self.assertEqual(service.TemplateAsset.query.count(), 2)

    def test_attachment_access_validation_and_followup_restriction(self):
        import tempfile
        from pathlib import Path
        from api import template_library
        url = '/api/outreach/templates'
        service.db.session.commit()
        self.assertEqual(self.client.get('/api/outreach/template-assets', headers=self.auth(self.owner)).status_code, 200)
        base = dict(name='Flyer', kind='initial', step=0, audience='general', subject='Hi', body='Hello')
        with tempfile.TemporaryDirectory() as directory, patch.object(template_library, 'PDF_DIRECTORY', Path(directory)):
            path = Path(directory) / 'PSA After School.pdf'
            path.write_bytes(b'not a PDF')
            catalog = self.client.get('/api/outreach/template-assets', headers=self.auth(self.admin)).get_json()['items']
            self.assertEqual(catalog, [])
            for changes in ({'attachment_file':'../api.py'}, {'attachment_file':path.name}, {'attachment_id':'missing'},
                            {'kind':'followup', 'step':1, 'attachment_file':path.name}):
                response = self.client.post(url, headers=self.auth(self.admin), json={**base, **changes})
                self.assertEqual(response.status_code, 400, response.get_json())
            with patch.object(template_library, 'MAX_PDF_BYTES', 4):
                path.write_bytes(b'%PDF-1.4\nToo large')
                response = self.client.post(url, headers=self.auth(self.admin), json={**base, 'attachment_file':path.name})
                self.assertEqual(response.status_code, 400)
        self.assertEqual(service.TemplateAsset.query.count(), 0)

    def test_missing_saved_attachment_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'unavailable or invalid'):
            service.build_email_message('from@example.test', 'Sender', 'to@example.test', 'Subject', 'Body', ['template-asset:' + 'a'*64])

    def upload_pdf(self, payload, name='campaign.pdf', actor=None):
        import io
        return self.client.post('/api/outreach/template-assets', headers=self.auth(actor or self.admin),
            data={'file':(io.BytesIO(payload),name)})

    def test_uploaded_pdfs_reused_every_time_without_reselection(self):
        service.db.session.commit()
        first=self.upload_pdf(b'%PDF-1.4\nFlyer One').get_json()
        second=self.upload_pdf(b'%PDF-1.4\nFlyer Two','schedule.pdf').get_json()
        ids=[first['id'],second['id']]
        template=self.template(attachment_ids=ids)
        schools=[self.school('PDF School One'),self.school('PDF School Two')]
        for school in schools:
            payload=self.payload(school,template)
            review=self.preview(payload).get_json()
            self.assertEqual(review['previews'][0]['attachments'],[first['name'],second['name']])
            response=self.create_batch(self.owner,**payload,preview_token=review['preview_token'])
            self.assertEqual(response.status_code,202,response.get_json())
        for recipient in outreach.OutreachRecipient.query.all():
            self.assertEqual(json.loads(recipient.attachments),['template-asset:'+key for key in ids])
        listed=self.client.get('/api/outreach/template-assets',headers=self.auth(self.admin)).get_json()['saved']
        self.assertEqual({item['id'] for item in listed},set(ids))

    def test_upload_permissions_type_duplicate_and_private_download(self):
        service.db.session.commit()
        self.assertEqual(self.upload_pdf(b'%PDF-1.4\nPrivate',actor=self.owner).status_code,403)
        self.assertEqual(self.upload_pdf(b'not pdf').status_code,400)
        self.assertEqual(self.upload_pdf(b'%PDF-1.4\nPrivate',name='file.exe').status_code,400)
        good=self.upload_pdf(b'%PDF-1.4\nPrivate',name='../Unsafe Name.pdf')
        self.assertEqual(good.status_code,201,good.get_json())
        data=good.get_json()
        self.assertNotIn('/',data['name'])
        duplicate=self.upload_pdf(b'%PDF-1.4\nPrivate',name='different.pdf').get_json()
        self.assertEqual(data['id'],duplicate['id'])
        self.assertEqual(service.TemplateAsset.query.count(),1)
        url='/api/outreach/template-assets/'+data['id']
        self.assertEqual(self.client.get(url,headers=self.auth(self.owner)).status_code,200)
        response=self.client.get(url,headers=self.auth(self.admin))
        self.assertEqual(response.data,b'%PDF-1.4\nPrivate')
        self.assertIn('attachment;',response.headers['Content-Disposition'])

    def test_explicit_followup_pdfs_and_count_and_size_limits(self):
        from api import template_library
        service.db.session.commit()
        assets=[self.upload_pdf(b'%PDF-1.4\n'+str(i).encode(),f'flyer{i}.pdf').get_json() for i in range(4)]
        template=self.template(kind='followup',step=1,attachment_ids=[assets[0]['id']])
        school=self.school('Followup With PDF',status='contacted')
        self.sent_email(school,8);self.sync_ready(self.owner)
        review=self.preview(self.payload(school,template)).get_json()
        self.assertEqual(review['previews'][0]['attachments'],[assets[0]['name']])
        response=self.create_batch(self.owner,**self.payload(school,template),preview_token=review['preview_token'])
        self.assertEqual(response.status_code,202,response.get_json())
        self.assertEqual(self.edit(template,attachment_ids=[a['id'] for a in assets]).status_code,400)
        with patch.object(template_library,'MAX_TEMPLATE_BYTES',1):
            self.assertEqual(self.edit(template,attachment_ids=[assets[0]['id']]).status_code,400)

    def import_preview(self, rows, actor=None):
        import io
        return self.client.post('/api/outreach/template-imports/preview',headers=self.auth(actor or self.admin),
            data={'file':(io.BytesIO(json.dumps(rows).encode()),'templates.json')})

    def import_commit(self, rid, actor=None):
        return self.client.post(f'/api/outreach/template-imports/{rid}/commit',headers=self.auth(actor or self.admin),json={})

    def test_rep_can_select_catalog_pdf_on_custom_email_without_a_template(self):
        service.db.session.commit()
        asset=self.upload_pdf(b'%PDF-1.4\nShared catalog').get_json()
        school=self.school('Catalog School')
        catalog=self.client.get('/api/outreach/template-assets',headers=self.auth(self.owner)).get_json()['saved']
        self.assertEqual(catalog[0]['id'],asset['id'])
        self.assertEqual(self.client.get('/api/outreach/template-assets').status_code,401)
        self.assertEqual(self.client.get('/api/outreach/template-assets/'+asset['id']).status_code,401)
        payload=dict(kind='custom',school_ids=[school.id],subject='Reviewed PDF',body='Body',attachment_ids=[asset['id']])
        self.assertEqual(self.create_batch(self.owner,**payload).status_code,409)
        review=self.preview(payload).get_json()
        self.assertEqual(review['previews'][0]['attachments'],[asset['name']])
        sent=self.create_batch(self.owner,**payload,preview_token=review['preview_token'])
        self.assertEqual(sent.status_code,202,sent.get_json())
        self.assertEqual(json.loads(outreach.OutreachRecipient.query.one().attachments),['template-asset:'+asset['id']])
        self.run_workers()
        self.assertEqual(self.get_batch(self.owner,sent.get_json()['batch_id'])['sent'],1)
        self.assertEqual(service.MailTemplate.query.count(),0)

    def test_catalog_selection_change_invalidates_review_and_empty_selection_has_no_flyers(self):
        service.db.session.commit()
        files=[self.upload_pdf(b'%PDF-1.4\n'+str(i).encode(),f'catalog{i}.pdf').get_json() for i in range(2)]
        school=self.school('Selection School')
        payload=dict(kind='initial',school_ids=[school.id],attachment_ids=[files[0]['id']])
        review=self.preview(payload).get_json()
        for ids in ([files[1]['id']],[]):
            response=self.create_batch(self.owner,**{**payload,'attachment_ids':ids},preview_token=review['preview_token'])
            self.assertEqual(response.status_code,409,response.get_json())
        empty=self.preview({**payload,'attachment_ids':[]}).get_json()
        self.assertEqual(empty['previews'][0]['attachments'],[])
        self.assertEqual(outreach.OutreachBatch.query.count(),0)

    def test_template_defaults_and_rep_extras_combine_without_library_mutation(self):
        service.db.session.commit()
        files=[self.upload_pdf(b'%PDF-1.4\n'+str(i).encode(),f'extra{i}.pdf').get_json() for i in range(4)]
        template=self.template(attachment_ids=[files[0]['id']])
        school=self.school('Extra School')
        payload=self.payload(school,template,attachment_ids=[files[0]['id'],files[1]['id']])
        review=self.preview(payload).get_json()
        self.assertEqual(review['previews'][0]['attachments'],[files[0]['name'],files[1]['name']])
        self.assertEqual(self.create_batch(self.owner,**payload,preview_token=review['preview_token']).status_code,202)
        snapshot=json.loads(service.MailTemplateVersion.query.filter_by(template_id=template['id'],revision=1).one().snapshot)
        self.assertEqual(snapshot['attachment_ids'],[files[0]['id']])
        too_many={**payload,'attachment_ids':[a['id'] for a in files[1:]]}
        self.assertEqual(self.preview(too_many).status_code,400)
        self.assertEqual(self.preview({**payload,'attachment_ids':['missing']}).status_code,400)

    def test_template_json_upload_preview_commit_repeat_and_preserve_later_edit(self):
        service.db.session.commit()
        row=dict(name='Uploaded intro',audience='general',kind='initial',step=0,subject='Hello {school name}',body='Hello from {my name}')
        preview=self.import_preview({'templates':[row,row]})
        self.assertEqual(preview.status_code,200,preview.get_json())
        plan=preview.get_json();self.assertEqual((plan['total'],plan['new']),(2,1))
        self.assertEqual(service.MailTemplate.query.count(),0)
        done=self.import_commit(plan['id'])
        self.assertEqual(done.get_json(),{'added':1,'skipped':1})
        self.assertEqual(self.import_commit(plan['id']).get_json(),done.get_json())
        item=self.client.get('/api/outreach/templates',headers=self.auth(self.owner)).get_json()['items'][0]
        self.assertEqual(self.edit(item,body='Admin updated text').status_code,200)
        again=self.import_preview(row).get_json()
        self.assertEqual(again['new'],0)
        self.assertEqual(self.import_commit(again['id']).get_json()['added'],0)
        self.assertEqual(service.MailTemplate.query.count(),1)
        self.assertEqual(service.MailTemplateVersion.query.count(),2)

    def test_template_imports_reject_bad_rows_and_are_admin_actor_bound(self):
        service.db.session.commit()
        row=dict(name='Valid',audience='general',kind='initial',step=0,subject='Hello',body='Hello')
        self.assertEqual(self.import_preview(row,self.owner).status_code,403)
        invalid=self.import_preview([row,{**row,'body':'Hello {unknown}'}])
        self.assertEqual(invalid.status_code,400)
        self.assertEqual(invalid.get_json()['rows'][0]['row'],2)
        self.assertEqual(service.MailTemplate.query.count(),0)
        plan=self.import_preview(row).get_json()
        self.assertEqual(self.import_commit(plan['id'],self.owner).status_code,403)
        other=service.User(name='Other Admin',email='anotheradmin@example.test',admin=True,password_hash='x')
        service.db.session.add(other);service.db.session.commit()
        self.assertEqual(self.import_commit(plan['id'],other).status_code,404)
        table=service.db.metadata.tables['mail_template_imports']
        service.db.session.execute(table.update().where(table.c.id==plan['id']).values(expires_at=service.utc_now()-__import__('datetime').timedelta(seconds=1)));service.db.session.commit()
        self.assertEqual(self.import_commit(plan['id']).status_code,409)

    def test_import_validates_catalog_references_and_json_encoding(self):
        service.db.session.commit()
        asset=self.upload_pdf(b'%PDF-1.4\nImported ref').get_json()
        row=dict(name='Imported with PDF',audience='general',kind='initial',step=0,subject='Hello',body='Hello',attachment_ids=[asset['id']])
        plan=self.import_preview([row]).get_json()
        self.assertEqual(plan['items'][0]['attachments'],[asset['name']])
        self.assertEqual(self.import_commit(plan['id']).status_code,200)
        self.assertEqual(self.import_preview([{**row,'attachment_ids':['0'*64]}]).status_code,400)
        import io
        response=self.client.post('/api/outreach/template-imports/preview',headers=self.auth(self.admin),data={'file':(io.BytesIO(b'{invalid'),'bad.json')})
        self.assertEqual(response.status_code,400)

    def test_original_chris_json_upload_uses_same_identity_as_builtin_import(self):
        from api.template_library import SEED
        service.db.session.commit()
        self.client.post('/api/outreach/templates/seed-winter-2027',headers=self.auth(self.admin))
        plan=self.import_preview(json.loads(SEED.read_text(encoding='utf-8'))).get_json()
        self.assertEqual((plan['total'],plan['new']),(16,0))
        self.assertEqual(self.import_commit(plan['id']).get_json()['added'],0)
        self.assertEqual(service.MailTemplate.query.count(),16)

    def test_admin_can_publish_existing_flyer_without_creating_a_template(self):
        import tempfile
        from pathlib import Path
        from api import template_library
        service.db.session.commit()
        path='/api/outreach/template-assets/publish'
        with tempfile.TemporaryDirectory() as directory,patch.object(template_library,'PDF_DIRECTORY',Path(directory)):
            filename='PSA After School.pdf'
            (Path(directory)/filename).write_bytes(b'%PDF-1.4\nPublish existing flyer')
            self.assertEqual(self.client.post(path,headers=self.auth(self.owner),json={'filename':filename}).status_code,403)
            response=self.client.post(path,headers=self.auth(self.admin),json={'filename':filename})
            self.assertEqual(response.status_code,201,response.get_json())
            catalog=self.client.get('/api/outreach/template-assets',headers=self.auth(self.owner)).get_json()['saved']
            self.assertEqual(catalog[0]['id'],response.get_json()['id'])
            self.assertEqual(service.MailTemplate.query.count(),0)
            self.assertEqual(self.client.post(path,headers=self.auth(self.admin),json={'filename':'../api.py'}).status_code,400)

    def test_unicode_template_preview_and_mime_preserve_original_characters(self):
        from email.header import decode_header,make_header
        school=self.school('Ecole test');school.school_name='\u00c9cole \u00b7 Fairfax';school.contact_name='Jos\u00e9';service.db.session.commit()
        subject='Enrichment \u00b7 {school name}'
        body='Hello {contact name} \u2014 caf\u00e9 \u2022 \u00a320 \u201cWinter\u201d'
        saved=self.template(subject=subject,body=body)
        review=self.preview(self.payload(school,saved)).get_json()['previews'][0]
        expected=render_copy(subject,body,school,self.owner)
        self.assertEqual(review['subject'],expected[0]);self.assertEqual(review['body_text'],expected[1])
        message=service.build_email_message(self.owner.email,self.owner.name,school.email,expected[0],expected[1],[])
        self.assertEqual(str(make_header(decode_header(message['Subject']))),expected[0])
        plain=next(part for part in message.walk() if part.get_content_type()=='text/plain')
        self.assertEqual(plain.get_payload(decode=True).decode(plain.get_content_charset()),expected[1])
        for broken in ('Broken \u00c2\u00b7 text','Broken \ufffd text'):
            with self.assertRaisesRegex(ValueError,'damaged characters'):validate_copy('Subject',broken)
