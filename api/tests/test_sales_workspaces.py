"""Cross-area isolation and shared mailbox safeguards; no provider calls."""
import unittest
import io
from datetime import datetime
from unittest.mock import patch, Mock

from api.tests import test_crm as crm_fixture
from api import api as svc
from api import outreach
from api.tests.test_outreach_batches import OutreachBase
from api.tests import test_agent_workflows as agent_fixture


class SalesWorkspaceTests(unittest.TestCase):
    setUp = crm_fixture.CRMTests.setUp
    tearDown = crm_fixture.CRMTests.tearDown
    auth = crm_fixture.CRMTests.auth

    def business_headers(self, user=None):
        return {**self.auth(user or self.owner), 'X-PSA-Workspace': 'business'}

    def business(self, owner=None):
        row = svc.SalesSchool(school_name='Cedar Coffee', email='sponsor@example.test', school_type='business',
                              sales_workspace='business', user_id=(owner or self.owner).id, status='pending')
        svc.db.session.add(row); svc.db.session.commit()
        return row

    def test_both_lists_overview_and_map_are_isolated_for_admin_too(self):
        business = self.business()
        for headers, expected in ((self.auth(self.admin), [self.a.id, self.b.id, self.c.id]),
                                  (self.business_headers(self.admin), [business.id])):
            data = self.client.get('/api/crm/schools', headers=headers).get_json()
            self.assertEqual(sorted(row['id'] for row in data['items']), sorted(expected))
            self.assertEqual(self.client.get('/api/crm/overview', headers=headers).get_json()['schools'], len(expected))
            data = self.client.get('/api/crm/map-accounts?stages=pending,contacted,meeting', headers=headers).get_json()
            self.assertNotIn('error', data)

    def test_direct_read_write_and_mixed_bulk_cannot_cross_area(self):
        business = self.business()
        for headers, denied_id in ((self.auth(self.admin), business.id), (self.business_headers(self.admin), self.a.id)):
            path = f'/api/sales-schools/{denied_id}'
            self.assertEqual(self.client.get(path, headers=headers).status_code, 404)
            self.assertEqual(self.client.patch(path, headers=headers, json={'status':'partner'}).status_code, 404)
            result = self.client.post('/api/crm/schools/bulk', headers=headers,
                                     json={'ids':[business.id,self.a.id], 'status':'partner'})
            self.assertEqual(result.status_code, 404, result.get_json())
        svc.db.session.refresh(self.a)
        self.assertEqual(self.a.status, 'contacted')

    def test_create_business_preserves_sponsorship_fields_and_school_defaults(self):
        body = dict(school_name='New Sponsor', email='new@example.test', industry='Retail',
                    status='partner', sponsorship_value='1250.00', user_id=self.other.id,
                    notes='Season sponsor', next_action='Renew in spring', next_action_at='2027-03-01T12:00:00')
        response = self.client.post('/api/add-school', headers=self.business_headers(self.admin), json=body)
        self.assertEqual(response.status_code, 201, response.get_json())
        row = svc.db.session.get(svc.SalesSchool, response.get_json()['id'])
        self.assertEqual((row.sales_workspace,row.school_type,row.industry,row.user_id), ('business','business','Retail',self.other.id))
        self.assertEqual(str(row.sponsorship_value), '1250.00')
        self.assertIsNotNone(row.closed_at)
        self.assertEqual(row.next_action, 'Renew in spring')
        self.assertEqual(self.a.sales_workspace, 'school')
        self.assertEqual(self.client.patch(f'/api/sales-schools/{row.id}', headers=self.business_headers(self.admin), json={'sponsorship_value':'NaN'}).status_code,400)

    def test_ownership_and_task_parent_checks_still_apply(self):
        business = self.business(self.other)
        self.assertEqual(self.client.get(f'/api/sales-schools/{business.id}', headers=self.business_headers()).status_code,404)
        # Includes an already-loaded identity map entry, not just a SQL miss.
        result = self.client.post('/api/crm/tasks', headers=self.business_headers(), json={'title':'Call school','school_id':self.a.id})
        self.assertEqual(result.status_code,404,result.get_json())
        result = self.client.post('/api/add-school', headers=self.business_headers(), json={'school_name':'No escalation','email':'x@example.test','user_id':self.admin.id})
        self.assertEqual(result.status_code,403,result.get_json())

    def test_business_contact_roles_and_global_stop_span_areas(self):
        business = self.business()
        response=self.client.post(f'/api/sales-schools/{business.id}/contacts',headers=self.business_headers(),json={'email':'marketing@example.test','roles':['marketing']})
        self.assertEqual(response.status_code,201,response.get_json())
        with svc.app.test_request_context('/api/profile',headers=self.business_headers()):
            svc.record_mail_signal('sponsor@example.test','optout','test-business-stop','Requested removal',actor_id=self.owner.id)
            svc.db.session.commit()
        self.assertTrue(svc.Contact.query.filter_by(email='sponsor@example.test').one().do_not_contact)

    def test_mailbox_daily_allowance_combines_both_areas(self):
        business=self.business()
        svc.db.session.add_all([
            svc.SentEmail(user_id=self.owner.id,school_name=self.a.school_name,school_email=self.a.email,sales_school_id=self.a.id),
            svc.SentEmail(user_id=self.owner.id,school_name=business.school_name,school_email=business.email,sales_school_id=business.id),
        ]);svc.db.session.commit()
        for headers in (self.auth(self.owner),self.business_headers()):
            data=self.client.get('/api/outreach/limits',headers=headers).get_json()
            self.assertEqual(data['sent_today'],2,data)
        business_mail=svc.SentEmail.query.filter_by(sales_school_id=business.id).one()
        self.assertEqual(business_mail.sales_workspace,'business')

    def test_business_uses_reviewed_copy_never_default_school_pitch(self):
        business=self.business()
        response=self.client.post('/api/email-preview',headers=self.business_headers(),json={'school_ids':[business.id],'kind':'initial','contact_mode':True})
        self.assertEqual(response.status_code,400,response.get_json())
        self.assertIn('Business Sales template',response.get_json()['error'])
        with patch.object(svc,'send_emails_over_connection') as sender:
            self.assertEqual(self.client.post('/api/send-email',headers=self.business_headers(),json={}).status_code,409)
            sender.assert_not_called()

    def test_invalid_workspace_and_record_moving_rejected(self):
        headers={**self.auth(self.admin),'X-PSA-Workspace':'everything'}
        self.assertEqual(self.client.get('/api/crm/schools',headers=headers).status_code,400)
        self.assertEqual(self.client.patch(f'/api/sales-schools/{self.a.id}',headers=self.auth(self.admin),json={'sales_workspace':'business'}).status_code,400)

    def test_production_browser_preflight_allows_workspace_header(self):
        response=self.client.options('/api/add-school',headers={
            'Origin':'https://www.salespsa.com', 'Access-Control-Request-Method':'POST',
            'Access-Control-Request-Headers':'Authorization,Content-Type,X-PSA-Workspace'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],'https://www.salespsa.com')
        self.assertIn('x-psa-workspace',response.headers['Access-Control-Allow-Headers'].lower())

    def test_school_references_not_available_in_business_workspace(self):
        for path in ('/api/crm/directory','/api/map-schools'):
            self.assertEqual(self.client.get(path,headers=self.business_headers(self.admin)).status_code,400)

    def test_business_without_email_can_be_worked_by_phone(self):
        response=self.client.post('/api/add-school',headers=self.business_headers(),json={'school_name':'Phone prospect','phone':'555-0100'})
        self.assertEqual(response.status_code,201,response.get_json())
        response=self.client.patch(f"/api/sales-schools/{response.get_json()['id']}",headers=self.business_headers(),json={'email':'','next_action':'Call owner'})
        self.assertEqual(response.status_code,200,response.get_json())

    def test_cached_contact_parent_does_not_cross_area(self):
        business=self.business()
        self.assertEqual(self.client.get(f'/api/sales-schools/{business.id}/contacts',headers=self.auth(self.admin)).status_code,404)
        self.assertEqual(self.client.get(f'/api/sales-schools/{self.a.id}/contacts',headers=self.business_headers(self.admin)).status_code,404)

    def test_business_discovery_uses_business_types_without_school_partner_sheet(self):
        seen=[]
        def provider(_url, params, **_kwargs):
            seen.append(params)
            return Mock(**{'raise_for_status.return_value':None,'json.return_value':{'status':'OK','results':[{'place_id':'business-p1','name':'Local Coffee','vicinity':'1 Main St','geometry':{'location':{'lat':38.85,'lng':-77.30}}}]}})
        with patch('api.finder.requests.get',side_effect=provider), patch.object(svc._FinderHooks,'partner_names',side_effect=AssertionError('School sheet must not load')):
            response=self.client.post('/api/find-schools',headers=self.business_headers(),json={'lat':38.85,'lng':-77.30,'keywords':['coffee shop']})
        self.assertEqual(response.status_code,200,response.get_json())
        self.assertEqual(response.get_json()['schools'][0]['school_name'],'Local Coffee')
        self.assertEqual(seen[0]['type'],'establishment')


class BusinessOutreachTests(OutreachBase):
    key = agent_fixture.AgentWorkflowTests.key

    def headers(self, user=None):
        return {**self.auth(user or self.owner), 'X-PSA-Workspace':'business'}

    def test_reviewed_business_send_runs_in_background_and_history_stays_separate(self):
        business=self.school('Coffee Sponsor',kind='business',sales_workspace='business')
        school=self.school('School prospect')
        body=dict(school_ids=[business.id],kind='custom',contact_mode=True,audience='all',
                  campaign_id='standard',contact_contexts={},subject='For [business_name]',
                  body='Hello [contact_name], sponsorship for [business_name]',attachment_ids=[])
        review=self.client.post('/api/email-preview',headers=self.headers(),json=body)
        self.assertEqual(review.status_code,200,review.get_json())
        self.assertEqual(review.get_json()['previews'][0]['subject'],'For Coffee Sponsor')
        queued=self.client.post('/api/outreach/batches',headers=self.headers(),json={**body,'preview_token':review.get_json()['preview_token']})
        self.assertEqual(queued.status_code,202,queued.get_json())
        batch=svc.db.session.get(outreach.OutreachBatch,queued.get_json()['batch_id'])
        self.assertEqual(batch.sales_workspace,'business')
        self.run_workers()
        self.assertEqual(self.fake.sent,[business.email])
        self.assertEqual(svc.SentEmail.query.one().sales_workspace,'business')
        self.assertEqual(self.client.get('/api/outreach/batches',headers=self.auth(self.owner)).get_json()['items'],[])
        self.assertEqual(len(self.client.get('/api/outreach/batches',headers=self.headers()).get_json()['items']),1)
        svc.db.session.refresh(school)
        self.assertEqual(school.status,'pending')

    def test_business_templates_are_separate_and_merge_business_name(self):
        business=self.school('Coffee Sponsor',kind='business',sales_workspace='business')
        body=dict(name='Sponsor intro',kind='initial',step=0,audience='marketing',subject='For {business name}',
                  body='Hello {contact name}, from {my name}',attachment_ids=[])
        response=self.client.post('/api/outreach/templates',headers=self.headers(self.admin),json=body)
        self.assertEqual(response.status_code,201,response.get_json())
        self.assertEqual(self.client.get('/api/outreach/templates',headers=self.auth(self.owner)).get_json()['items'],[])
        self.assertEqual(len(self.client.get('/api/outreach/templates',headers=self.headers()).get_json()['items']),1)
        from api.template_library import render_copy
        self.assertEqual(render_copy(body['subject'],body['body'],business,self.owner)[0],'For Coffee Sponsor')

    def test_business_csv_alias_and_stale_area_import_rejected(self):
        response=self.client.post('/api/contact-imports/preview',headers=self.headers(),data={'file':(io.BytesIO(b'business_name,email,contact_role\nCoffee Sponsor,sponsor@example.test,marketing\n'),'businesses.csv')})
        self.assertEqual(response.status_code,200,response.get_json())
        data=response.get_json()
        denied=self.client.post(f"/api/contact-imports/{data['id']}/commit",headers=self.auth(self.owner),json={'file_hash':data['file_hash'],'decisions':{}})
        self.assertIn(denied.status_code,(404,409),denied.get_json())

    def test_agent_business_operations_default_to_business_and_keep_permissions(self):
        _,headers=self.key(scope='write')
        response=self.client.post('/api/agent/v1/operations/psa_create_business',headers=headers,json={'business_name':'AI Sponsor','email':'ai-sponsor@example.test','industry':'Retail'})
        self.assertEqual(response.status_code,201,response.get_json())
        record_id=response.get_json()['id']
        response=self.client.post('/api/agent/v1/operations/psa_businesses',headers=headers,json={})
        self.assertEqual([row['id'] for row in response.get_json()['items']],[record_id])
        self.assertEqual(self.client.get('/api/agent/v1/schools',headers=headers).get_json()['items'],[])
        response=self.client.post('/api/agent/v1/operations/psa_edit_business',headers=headers,json={'business_id':record_id,'sponsorship_value':'250.00','notes':'Interested'})
        self.assertEqual(response.status_code,200,response.get_json())
        response=self.client.post('/api/agent/v1/operations/psa_edit_business',headers=headers,json={'business_id':record_id,'user_id':self.other.id})
        self.assertEqual(response.status_code,403,response.get_json())

    def test_agent_cannot_read_or_refresh_school_sources_from_business_sales(self):
        _,headers=self.key(scope='full',user=self.admin)
        with patch.object(svc, 'load_PSA_school_sheet', side_effect=AssertionError('School source must not load')):
            for operation in ('psa_directory','psa_map_layers','psa_refresh_map_layers'):
                response=self.client.post(f'/api/agent/v1/operations/{operation}',headers=headers,json={'workspace':'business'})
                self.assertEqual(response.status_code,400,(operation,response.get_json()))
                self.assertIn('School Sales',response.get_json()['error'])


class BusinessSequenceWorkerTests(OutreachBase):
    """Exercise persisted workspace propagation with no HTTP context at dispatch."""
    from api.tests import test_sequences as fixture
    def setUp(self):
        super().setUp()
        clock=patch.object(svc,'utc_now',return_value=datetime(2026,11,5,15))
        self.time=clock.start();self.addCleanup(clock.stop)
        self.sync_ready(self.owner)
        def fresh(user):
            state=svc.db.session.get(svc.MailSyncState,user.id)
            state.last_success_at=svc.utc_now();state.pending_count=0;state.last_error=None
            svc.db.session.commit();return {'ready':True}
        sync=patch.object(svc,'sync_user_mailbox',side_effect=fresh)
        sync.start();self.addCleanup(sync.stop)
    definition = fixture.SequenceTests.definition
    original = fixture.SequenceTests.original
    settings = fixture.SequenceTests.settings
    enroll = fixture.SequenceTests.enroll
    move_to_due = fixture.SequenceTests.move_to_due
    approve = fixture.SequenceTests.approve

    def auth(self, user):
        return {**super().auth(user), 'X-PSA-Workspace':'business'}

    def school(self, name, **kwargs):
        return super().school(name, kind='business', sales_workspace='business', **kwargs)

    def test_business_sequence_keeps_area_and_thread_when_worker_runs(self):
        sequence,_=self.definition()
        school,original=self.original()
        enrollment,_=self.enroll(self.settings(sequence,original))
        self.assertEqual(enrollment.sales_workspace,'business')
        step=self.move_to_due(enrollment)
        self.approve(step)
        self.assertEqual(svc.schedule_sequences(),1)
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence').one()
        self.assertEqual(batch.sales_workspace,'business')
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[school.email])
        self.assertEqual(self.fake.messages[0]['In-Reply-To'],f'<intro-{original.id}@example.test>')
        school_headers=OutreachBase.auth(self,self.owner)
        self.assertEqual(self.client.get('/api/outreach/sequence-enrollments',headers=school_headers).get_json()['items'],[])
        self.assertEqual(self.client.get('/api/outreach/batches',headers=school_headers).get_json()['items'],[])


class BusinessCampaignWorkerTests(OutreachBase):
    from api.tests import test_campaign_plans as fixture
    template = fixture.CampaignPlanTests.template
    prepare = fixture.CampaignPlanTests.prepare
    action = fixture.CampaignPlanTests.action
    approve = fixture.CampaignPlanTests.approve
    send_batches = fixture.CampaignPlanTests.send_batches
    key = agent_fixture.AgentWorkflowTests.key

    def setUp(self):
        super().setUp()
        clock=patch.object(svc,'utc_now',return_value=datetime(2026,11,9,15))
        self.time=clock.start();self.addCleanup(clock.stop)
        flag=patch.dict('os.environ',{'CAMPAIGN_AUTOMATION_ENABLED':'true'})
        flag.start();self.addCleanup(flag.stop)
        self.sync_ready(self.owner)
        self.key_data,self.headers=self.key(capabilities=['outreach:read','outreach:prepare','outreach:send'])
        self.headers['X-PSA-Workspace']='business'

    def auth(self, user):
        return {**super().auth(user), 'X-PSA-Workspace':'business'}

    def school(self, name, **kwargs):
        return super().school(name, kind='business', sales_workspace='business', **kwargs)

    def test_business_campaign_stays_private_and_background_batch_keeps_area(self):
        school=self.school('Campaign sponsor')
        plan=self.prepare([school])
        path='/api/outreach/campaign-plans/'+plan['id']
        school_headers=OutreachBase.auth(self,self.owner)
        self.assertEqual(self.client.get(path,headers=school_headers).status_code,404)
        self.assertEqual(self.client.post(path+'/approve',headers=school_headers,json={'revision':plan['revision'],'confirm':'AUTHORIZE_CAMPAIGN'}).status_code,404)
        self.approve(plan)
        self.assertEqual(svc.schedule_campaigns(),1)
        batch=outreach.OutreachBatch.query.one()
        self.assertEqual(batch.sales_workspace,'business')
        self.send_batches()
        self.assertEqual(self.fake.sent,[school.email])
        self.assertEqual(svc.SentEmail.query.one().sales_workspace,'business')
        self.assertEqual(self.client.get('/api/outreach/batches',headers=school_headers).get_json()['items'],[])
