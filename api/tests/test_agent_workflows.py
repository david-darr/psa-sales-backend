from datetime import timedelta
from api.tests.test_outreach_batches import OutreachBase
from api import api as svc,outreach

BASE='/api/agent/v1'
class AgentWorkflowTests(OutreachBase):
    def key(self,user=None,capabilities=None,scope='read'):
        user=user or self.owner
        response=self.client.post('/api/agent-keys',headers=self.auth(user),json=dict(name='Test agent',scope=scope,
            expires_in_days=7,capabilities=capabilities or [],confirm_send=True))
        self.assertEqual(response.status_code,201,response.get_json())
        result=response.get_json();return result,{'Authorization':'Bearer '+result['key']}
    def draft(self,headers,school=None):
        school=school or self.school('Agent Draft School')
        result=self.client.post(BASE+'/outreach/drafts',headers=headers,json=dict(kind='custom',school_ids=[school.id],
            audience='all',subject='Hi [school_name]',body='Hello [contact_name]',attachment_ids=[]))
        self.assertEqual(result.status_code,201,result.get_json())
        return result.get_json(),school
    def approve(self,draft):
        result=self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/approve',headers=self.auth(self.owner),json=dict(revision=draft['revision']))
        self.assertEqual(result.status_code,200,result.get_json());return result.get_json()
    def execute(self,draft,headers,body=None):
        return self.client.post(BASE+'/outreach/drafts/'+draft['id']+'/execute',headers=headers,json=body or {})

    def test_old_keys_have_no_new_capabilities(self):
        for scope in ('read','write'):
            key,headers=self.key(scope=scope)
            self.assertEqual(key['capabilities'],[])
            self.assertEqual(self.client.post(BASE+'/outreach/drafts',headers=headers,json={}).status_code,403)
            self.assertEqual(self.client.post(BASE+'/imports/preview',headers=headers,json={}).status_code,403)
            self.assertEqual(self.client.get(BASE+'/outreach/templates',headers=headers).status_code,403)
        result=self.client.post('/api/agent-keys',headers=self.auth(self.owner),json=dict(name='Unsafe implicit',scope='read',expires_in_days=7,capabilities=['outreach:send']))
        self.assertEqual(result.status_code,400)

    def test_prepare_approve_execute_idempotent_and_audited(self):
        key,headers=self.key(capabilities=['outreach:prepare','outreach:send'])
        draft,school=self.draft(headers)
        self.assertNotIn('preview_token',draft['preview'])
        self.assertEqual(outreach.OutreachBatch.query.count(),0)
        self.assertEqual(self.execute(draft,headers).status_code,409)
        self.assertEqual(self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/approve',headers=headers,json={'revision':1}).status_code,422)
        approved=self.approve(draft)
        result=self.execute(draft,headers)
        self.assertEqual(result.status_code,202,result.get_json())
        self.assertEqual(self.execute(draft,headers).get_json()['batch_id'],result.get_json()['batch_id'])
        self.assertEqual(outreach.OutreachBatch.query.count(),1)
        batch=outreach.OutreachBatch.query.one();outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[school.email])
        saved=svc.AgentOutreachDraft.query.one()
        self.assertEqual((saved.key_id,saved.approved_by,saved.approval_id),(key['id'],self.owner.id,approved['approval_id']))
        self.assertEqual([e.event for e in svc.AgentOutreachEvent.query.order_by(svc.AgentOutreachEvent.id)],['prepared','approved','queued'])

    def test_prepare_cannot_execute_and_send_key_cannot_approve(self):
        _,prepare=self.key(capabilities=['outreach:prepare']);draft,_=self.draft(prepare);self.approve(draft)
        self.assertEqual(self.execute(draft,prepare).status_code,403)
        _,different=self.key(capabilities=['outreach:send'])
        self.assertEqual(self.execute(draft,different).status_code,404)

    def test_other_sender_admin_and_forged_actor_are_rejected(self):
        _,headers=self.key(capabilities=['outreach:prepare','outreach:send']);draft,school=self.draft(headers)
        self.assertEqual(self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/approve',headers=self.auth(self.admin),json=dict(revision=1)).status_code,404)
        self.assertEqual(self.execute(draft,headers,{'sender_id':self.admin.id}).status_code,400)
        _,other=self.key(self.other,capabilities=['outreach:prepare'])
        self.assertEqual(self.client.post(BASE+'/outreach/drafts',headers=other,json=dict(kind='initial',school_ids=[school.id])).status_code,403)

    def test_revoke_after_queue_blocks_worker(self):
        _,headers=self.key(capabilities=['outreach:prepare','outreach:send']);draft,_=self.draft(headers)
        self.approve(draft);queued=self.execute(draft,headers).get_json()
        result=self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/revoke',headers=self.auth(self.owner),json=dict(revision=1))
        self.assertEqual(result.status_code,200)
        batch=svc.db.session.get(outreach.OutreachBatch,queued['batch_id']);outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])

    def test_expired_or_revoked_key_blocks_queued_mail(self):
        key,headers=self.key(capabilities=['outreach:prepare','outreach:send']);draft,_=self.draft(headers)
        self.approve(draft);self.execute(draft,headers)
        stored=svc.db.session.get(svc.AgentApiKey,key['id']);stored.revoked_at=svc.utc_now();svc.db.session.commit()
        batch=outreach.OutreachBatch.query.one();outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])
        self.assertEqual(self.execute(draft,headers).status_code,401)

    def test_stale_copy_ownership_and_expiry_fail_closed(self):
        _,headers=self.key(capabilities=['outreach:prepare','outreach:send']);draft,school=self.draft(headers);self.approve(draft)
        school.contact_name='Changed';svc.db.session.commit()
        self.assertEqual(self.execute(draft,headers).status_code,409)
        saved=svc.AgentOutreachDraft.query.one();saved.expires_at=svc.utc_now()-timedelta(seconds=1);svc.db.session.commit()
        self.assertEqual(self.execute(draft,headers).status_code,409)
        self.assertEqual(outreach.OutreachBatch.query.count(),0)

    def test_import_uses_common_preview_commit_and_dedupe(self):
        _,headers=self.key(capabilities=['schools:import'])
        rows=[dict(school_name='Imported by agent',email='principal@agent.example.test',contact_role='principal_ap')]
        preview=self.client.post(BASE+'/imports/preview',headers=headers,json=dict(rows=rows))
        self.assertEqual(preview.status_code,200,preview.get_json());data=preview.get_json()
        self.assertEqual(svc.SalesSchool.query.count(),0)
        path=BASE+'/imports/'+data['id']+'/commit';body=dict(file_hash=data['file_hash'])
        first=self.client.post(path,headers=headers,json=body)
        self.assertEqual(first.status_code,200,first.get_json())
        self.assertEqual(self.client.post(path,headers=headers,json=body).get_json(),first.get_json())
        self.assertEqual(svc.SalesSchool.query.count(),1)
        self.assertEqual(svc.SchoolContact.query.count(),1)
        self.assertEqual(svc.SalesSchool.query.one().user_id,self.owner.id)

    def test_template_and_reply_reads_stay_scoped(self):
        _,headers=self.key(capabilities=['outreach:read'])
        self.assertEqual(self.client.get(BASE+'/outreach/templates',headers=headers).status_code,200)
        self.assertEqual(self.client.get(BASE+'/outreach/attachments',headers=headers).status_code,200)
        other=self.sent_email(self.school('Other conversation',owner=self.other),1,owner=self.other,responded=True)
        self.assertEqual(self.client.get(BASE+'/outreach/replies',headers=headers).get_json()['total'],0)
        self.assertEqual(self.client.get(BASE+f'/outreach/replies/{other.id}',headers=headers).status_code,404)

    def test_refresh_invalidates_prior_approval_and_old_revision(self):
        _,headers=self.key(capabilities=['outreach:prepare','outreach:send']);draft,_=self.draft(headers);approved=self.approve(draft)
        response=self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/refresh',headers=self.auth(self.owner),json=dict(revision=1))
        self.assertEqual(response.status_code,200,response.get_json())
        refreshed=response.get_json();self.assertEqual(refreshed['revision'],2)
        self.assertIsNone(refreshed['approval_id'])
        self.assertEqual(self.execute(draft,headers).status_code,409)
        self.assertEqual(self.client.post('/api/agent-outreach-drafts/'+draft['id']+'/approve',headers=self.auth(self.owner),json=dict(revision=1)).status_code,409)
        current=self.approve(refreshed);self.assertNotEqual(current['approval_id'],approved['approval_id'])
        self.assertEqual(self.execute(draft,headers).status_code,202)

    def test_key_expiry_and_kill_switch_block_dispatch(self):
        from unittest.mock import patch
        import os
        key,headers=self.key(capabilities=['outreach:prepare','outreach:send']);draft,_=self.draft(headers);self.approve(draft);self.execute(draft,headers)
        batch=outreach.OutreachBatch.query.one()
        with patch.dict(os.environ,{'AGENT_API_ENABLED':'false'}):
            self.assertIsNotNone(svc.agent_batch_guard(batch.id))
            self.assertEqual(self.execute(draft,headers).status_code,503)
        saved=svc.db.session.get(svc.AgentApiKey,key['id']);saved.expires_at=svc.utc_now()-timedelta(seconds=1);svc.db.session.commit()
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])
        self.assertEqual(self.execute(draft,headers).status_code,401)

    def test_wrong_actor_cannot_read_or_commit_import(self):
        _,headers=self.key(capabilities=['schools:import'])
        preview=self.client.post(BASE+'/imports/preview',headers=headers,json=dict(rows=[dict(school_name='Private import',email='private@example.test')])).get_json()
        _,other=self.key(self.other,capabilities=['schools:import'])
        self.assertEqual(self.client.post(BASE+'/imports/'+preview['id']+'/commit',headers=other,json=dict(file_hash=preview['file_hash'])).status_code,404)
        for row in (dict(school_name='x',email='a@example.test',user_id=str(self.admin.id)),dict(school_name='x',email='a@example.test',contact_role=['principal_ap'])):
            self.assertEqual(self.client.post(BASE+'/imports/preview',headers=headers,json=dict(rows=[row])).status_code,400)

    def test_prepare_blocks_mailbox_and_actor_overrides(self):
        _,headers=self.key(capabilities=['outreach:prepare'])
        school=self.school('Forged Sender')
        response=self.client.post(BASE+'/outreach/drafts',headers=headers,json=dict(kind='initial',school_ids=[school.id],sender_id=self.other.id,approved=True))
        self.assertEqual(response.status_code,400)
        self.assertEqual(self.client.post(BASE+'/outreach/check-replies',headers=headers,json=dict(user_id=self.other.id)).status_code,400)
        self.assertEqual(self.client.get('/api/agent-outreach-drafts',headers=self.auth(self.other)).get_json()['items'],[])
        self.assertEqual(outreach.OutreachBatch.query.count(),0)
