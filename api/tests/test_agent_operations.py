import base64
import json
from pathlib import Path
from unittest.mock import patch
from api.tests.test_outreach_batches import OutreachBase
from api.tests import test_agent_workflows as workflow_tests
from api import api as svc
from api.agent_operations import OPERATIONS

BASE='/api/agent/v1'

class AgentOperationsTests(OutreachBase):
    key=workflow_tests.AgentWorkflowTests.key

    def op(self,name,headers,data=None):
        return self.client.post(BASE+'/operations/'+name,headers=headers,json=data or {})

    def test_inventory_matches_real_handlers_and_reports_permissions(self):
        _,headers=self.key()
        response=self.client.get(BASE+'/capabilities',headers=headers)
        self.assertEqual(response.status_code,200,response.get_json())
        items=response.get_json()['operations']
        self.assertEqual(len(items),len(OPERATIONS))
        self.assertTrue(all(i['available'] for i in items),[i['name'] for i in items if not i['available']])
        self.assertFalse(next(i for i in items if i['name']=='psa_upload_pdf')['authorized'])
        self.assertIn('approval',' '.join(response.get_json()['human_only']))

    def test_old_keys_and_rep_cannot_gain_admin_management(self):
        _,headers=self.key(self.admin,scope='write')
        for name in ('psa_create_template','psa_create_commission','psa_set_team_access'):
            self.assertEqual(self.op(name,headers).status_code,403)
        for scope in ('library:manage','commissions:manage','team:manage'):
            response=self.client.post('/api/agent-keys',headers=self.auth(self.owner),json=dict(name='No escalation',scope='write',expires_in_days=7,capabilities=[scope]))
            self.assertEqual(response.status_code,403,response.get_json())

    def test_contact_add_edit_ownership_and_forged_fields(self):
        _,headers=self.key(scope='write')
        school=self.school('Chat contact')
        created=self.op('psa_add_contact',headers,dict(school_id=school.id,email='pta@example.test',name='Taylor',roles=['pta_pto']))
        self.assertEqual(created.status_code,201,created.get_json())
        contact=created.get_json()
        response=self.op('psa_edit_contact',headers,dict(school_id=school.id,link_id=contact['id'],version=contact['version'],contact_version=contact['contact_version'],name='Taylor updated'))
        self.assertEqual(response.status_code,200,response.get_json())
        stale=self.op('psa_edit_contact',headers,dict(school_id=school.id,link_id=contact['id'],version=contact['version'],contact_version=contact['contact_version'],name='Stale'))
        self.assertEqual(stale.status_code,409)
        foreign=self.school('Foreign contact',owner=self.other)
        self.assertEqual(self.op('psa_add_contact',headers,dict(school_id=foreign.id,email='bad@example.test')).status_code,404)
        self.assertEqual(self.op('psa_add_contact',headers,dict(school_id=school.id,email='bad@example.test',actor_id=self.admin.id)).status_code,400)

    def test_library_upload_create_version_and_admin_demotion(self):
        _,headers=self.key(self.admin,capabilities=['library:manage','outreach:read'])
        pdf=b'%PDF-1.4\nlocal fixture\n%%EOF'
        upload=self.op('psa_upload_pdf',headers,dict(filename='Chat flyer.pdf',encoded=base64.b64encode(pdf).decode()))
        self.assertEqual(upload.status_code,201,upload.get_json())
        asset=upload.get_json()
        created=self.op('psa_create_template',headers,dict(name='Chat introduction',kind='initial',audience='general',subject='Hello [school_name]',body='Hello [contact_name]',attachment_ids=[asset['id']]))
        self.assertEqual(created.status_code,201,created.get_json())
        row=created.get_json()
        versions=self.op('psa_template_versions',headers,dict(template_id=row['id']))
        self.assertEqual(versions.status_code,200,versions.get_json())
        self.assertIn(asset['id'],json.dumps(versions.get_json()))
        self.admin.admin=False;svc.db.session.commit()
        self.assertEqual(self.op('psa_upload_pdf',headers,dict(filename='Other.pdf',encoded=base64.b64encode(pdf).decode())).status_code,403)

    def test_invalid_uploads_and_non_upload_body_limit(self):
        _,headers=self.key(self.admin,capabilities=['library:manage'],scope='write')
        for filename,payload in [('bad.pdf','!!!'),('../bad.pdf',base64.b64encode(b'%PDF-1').decode()),('image.pdf',base64.b64encode(b'not pdf').decode())]:
            self.assertEqual(self.op('psa_upload_pdf',headers,dict(filename=filename,encoded=payload)).status_code,400)
        self.assertEqual(self.op('psa_create_template',headers,dict(name='x'*40000)).status_code,413)

    def test_commission_create_history_and_stale_edit(self):
        _,headers=self.key(self.admin,capabilities=['commissions:manage'])
        school=self.school('Chat commission')
        data=dict(sales_school_id=school.id,season='Winter 2027',program='Enrichment',rep_id=self.owner.id,sale_type='new',gross='10000',leagueapps=True,cash_expenses='650',rep_payout='900')
        created=self.op('psa_create_commission',headers,data)
        self.assertEqual(created.status_code,201,created.get_json())
        row=created.get_json();self.assertEqual(row['director_remainder'],450)
        history=self.op('psa_commission_history',headers,dict(record_id=row['id']))
        self.assertEqual(history.status_code,200);self.assertEqual(len(history.get_json()),1)
        changed=self.op('psa_edit_commission',headers,dict(**data,record_id=row['id'],revision=row['revision'],notes='Corrected'))
        self.assertEqual(changed.status_code,200,changed.get_json())
        self.assertEqual(self.op('psa_edit_commission',headers,dict(**data,record_id=row['id'],revision=row['revision'])).status_code,409)

    def test_exact_dispatch_no_approval_or_destination_passthrough(self):
        _,headers=self.key()
        for name in ('approve','psa_approve_campaign','../../login','psa_human_request'):
            self.assertIn(self.op(name,headers).status_code,(404,405))
        self.assertEqual(self.op('psa_find_schools',headers,dict(address='12345',url='https://elsewhere.test')).status_code,400)
        with patch.dict(svc.app.view_functions,{'find_schools':lambda: svc.jsonify(result='local fake provider')}):
            found=self.op('psa_find_schools',headers,dict(address='12345',radius_km=10))
        self.assertEqual(found.status_code,200,found.get_json())
        self.assertEqual(found.get_json()['result'],'local fake provider')

    def test_assignment_preview_claim_and_stale_permissions(self):
        _,admin_headers=self.key(self.admin,scope='write')
        school=self.school('Move from chat')
        preview=self.op('psa_assignment_preview',admin_headers,dict(ids=[school.id],user_id=None))
        self.assertEqual(preview.status_code,200,preview.get_json())
        committed=self.op('psa_assignment_commit',admin_headers,dict(review_id=preview.get_json()['id']))
        self.assertEqual(committed.status_code,200,committed.get_json())
        key,headers=self.key(scope='write')
        self.assertEqual(self.op('psa_claim_school',headers,dict(school_id=school.id)).status_code,200)
        self.client.delete('/api/agent-keys/'+str(key['id']),headers=self.auth(self.owner))
        self.assertEqual(self.op('psa_claim_school',headers,dict(school_id=school.id)).status_code,401)

    def test_both_bridges_generated_contract_is_current(self):
        manifest=json.loads((Path(__file__).parents[2]/'integrations/agent-operations.json').read_text(encoding='utf-8'))
        self.assertEqual({t['name'] for t in manifest},{o['name'] for o in OPERATIONS}|{'psa_capabilities','psa_prepare_reply'})
        for tool in manifest:
            self.assertNotIn('approve',tool['name'])
            self.assertFalse({'url','actor_id','user_token','access_token','preview_token'} & set(tool['inputSchema']['properties']))

    def test_chat_reply_requires_human_approval_and_preserves_thread(self):
        _,headers=self.key(capabilities=['outreach:prepare','outreach:send'])
        school=self.school('Chat answered',status='replied')
        original=self.sent_email(school,10,responded=True)
        svc.db.session.add(svc.SentMessage(sent_email_id=original.id,message_id='<chat-original@test>',kind='outreach',subject='Original'))
        svc.db.session.commit()
        prepared=self.client.post(BASE+'/outreach/reply-drafts',headers=headers,json=dict(email_id=original.id,subject='Re: Original',message='Thanks for your interest'))
        self.assertEqual(prepared.status_code,201,prepared.get_json())
        draft=prepared.get_json();self.assertNotIn('preview_token',draft['preview'])
        url=BASE+'/outreach/drafts/'+draft['id']+'/execute'
        self.assertEqual(self.client.post(url,headers=headers,json={}).status_code,409)
        approved=self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/approve',headers=self.auth(self.owner),json=dict(revision=draft['revision']))
        self.assertEqual(approved.status_code,200,approved.get_json())
        queued=self.client.post(url,headers=headers,json={})
        self.assertEqual(queued.status_code,202,queued.get_json())
        self.assertEqual(self.client.post(url,headers=headers,json={}).get_json()['batch_id'],queued.get_json()['batch_id'])
        self.run_workers()
        self.assertEqual(self.fake.sent,[school.email])
        self.assertEqual(self.fake.messages[0]['In-Reply-To'],'<chat-original@test>')
        self.assertEqual(svc.AgentOutreachDraft.query.one().status,'queued')
        self.assertEqual(self.client.post(url,headers=headers,json={'subject':'Override'}).status_code,400)
