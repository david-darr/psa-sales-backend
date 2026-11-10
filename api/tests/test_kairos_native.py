"""Native Kairos broker + real PSA handlers, fake UI storage and SMTP only."""
import importlib
import json
import sys
import types
import base64
import os
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime,timezone
from urllib.parse import urlsplit,parse_qsl
from api.tests.test_outreach_batches import OutreachBase
from api import api as svc,outreach

# Test the committed, source-only distribution by default, not machine-local state.
_bundle=tempfile.TemporaryDirectory(prefix='psa-native-test-')
if os.environ.get('PSA_KAIROS_TAB_DIR'):
    TAB=Path(os.environ['PSA_KAIROS_TAB_DIR'])
else:
    with zipfile.ZipFile(Path(__file__).resolve().parents[2]/'integrations/kairos/psa_command.zip') as bundle:
        bundle.extractall(_bundle.name)
    TAB=Path(_bundle.name)/'psa_command'
package=types.ModuleType('psa_native_fixture');package.__path__=[str(TAB)];sys.modules[package.__name__]=package
native=importlib.import_module('psa_native_fixture.human_session')
catalog=importlib.import_module('psa_native_fixture.catalog')

class Storage:
    def __init__(self):self.data={}
    def read_json(self,name,default):return self.data.get(name,default)
    def write_json(self,name,value):self.data[name]=value
    def encrypt(self,value):return 'test-encrypted:'+base64.b64encode(value.encode()).decode()
    def decrypt(self,value):return base64.b64decode(value.removeprefix('test-encrypted:')).decode()

class KairosNativeTests(OutreachBase):
    def test_business_catalog_upload_and_permissions_from_fresh_chats(self):
        self.owner.admin=True;svc.db.session.commit()
        self.connect(capabilities=['outreach:read','library:manage'])
        # Two independently built connection maps represent fresh chat sessions.
        first=self.agent();second=self.agent()
        self.assertEqual(catalog.call_tool('psa_connection',{},first)['id'],self.owner.id)
        self.assertEqual(catalog.call_tool('psa_connection',{},second)['id'],self.owner.id)
        report=catalog.call_tool('psa_capabilities',{},second)
        self.assertTrue(all(row['available'] for row in report['operations']))
        data=dict(filename='Chat catalog.pdf',encoded=base64.b64encode(b'%PDF-1.4\n'+b'0'*70000+b'\n%%EOF').decode())
        count=len(self.calls)
        preview=catalog.call_tool('psa_upload_pdf',data,first)
        self.assertTrue(preview['confirmation_required'])
        self.assertNotIn(data['encoded'],json.dumps(preview))
        self.assertEqual(len(self.calls),count)
        saved=catalog.call_tool('psa_upload_pdf',{**data,'confirm':True},second)
        self.assertEqual(saved['bytes'],70015)
        with self.assertRaises(ValueError):catalog.call_tool('psa_approve_campaign',{},first)
        with self.assertRaises(catalog.ApiError):catalog.call_tool('psa_create_commission',dict(sales_school_id=1,season='Winter',program='A',rep_id=self.owner.id,sale_type='new',gross='10',leagueapps=False,cash_expenses='0',confirm=True),first)
    def setUp(self):
        super().setUp()
        self.owner.set_password('Only-a-local-fixture');svc.db.session.commit()
        self.storage=Storage();self.connections={};self.calls=[]
        def save(user,system,url=None,key=None,clear=False):
            if clear:self.connections.pop(user,None)
            else:self.connections[user]=(url,self.storage.encrypt(key))
        def transport(method,url,headers,body):
            parsed=urlsplit(url);self.assertEqual(parsed.hostname,'127.0.0.1')
            self.calls.append((method,parsed.path))
            response=self.client.open(parsed.path,method=method,headers=headers,**({'data':body} if isinstance(body,bytes) else {'json':body}),query_string=dict(parse_qsl(parsed.query)))
            return response.status_code,response.get_json()
        self.native=native.HumanSession(self.storage,save,transport=transport);self.transport=transport
    def connect(self,**changes):
        options=dict(user='chris',base='http://127.0.0.1:5555/api/agent/v1',email=self.owner.email,password='Only-a-local-fixture',
            capabilities=['outreach:read','outreach:prepare','outreach:send','schools:import'],confirm_send=True)
        options.update(changes);return self.native.connect(**options)
    def agent(self):
        url,encrypted=self.connections['chris']
        return {'psa':catalog.Connection('psa',url,self.storage.decrypt(encrypted),transport=self.transport),'taskbar':None}

    def test_native_end_to_end_without_website_or_agent_approval_tool(self):
        connected=self.connect();school=self.school('Native Kairos School')
        args=dict(kind='custom',school_ids=[school.id],subject='Hello [school_name]',body='Hi [contact_name]',audience='all')
        preview=catalog.call_tool('psa_prepare_outreach',args,self.agent());self.assertTrue(preview['confirmation_required'])
        draft=catalog.call_tool('psa_prepare_outreach',{**args,'confirm':True},self.agent())
        self.assertEqual(draft['status'],'awaiting')
        with self.assertRaises(catalog.ApiError):catalog.call_tool('psa_execute_approved_outreach',dict(draft_id=draft['id'],confirm=True),self.agent())
        review=self.native.request('chris','GET','/api/agent-outreach-drafts/'+draft['id'])
        self.assertEqual(review['preview']['previews'][0]['email'],school.email)
        self.native.request('chris','POST','/api/agent-outreach-drafts/'+draft['id']+'/approve',{'revision':review['revision']})
        queued=catalog.call_tool('psa_execute_approved_outreach',dict(draft_id=draft['id'],confirm=True),self.agent())
        repeated=catalog.call_tool('psa_execute_approved_outreach',dict(draft_id=draft['id'],confirm=True),self.agent())
        self.assertEqual(queued['batch_id'],repeated['batch_id'])
        batch=svc.db.session.get(outreach.OutreachBatch,queued['batch_id']);outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[school.email])
        self.assertNotIn('access_token',str(connected));self.assertNotIn('Only-a-local-fixture',str(self.storage.data))
        self.assertFalse(any('/approve' in (tool['path'] or '') or 'human-session' in (tool['path'] or '') for tool in catalog.TOOLS))
        self.assertNotIn('/api/login',[path for method,path in self.calls if method=='GET'])

    def test_human_session_is_private_and_not_a_generic_proxy(self):
        self.connect()
        self.assertNotIn('token',self.native.status('chris'))
        self.assertFalse(self.native.status('another-user')['connected'])
        with self.assertRaises(catalog.ApiError):self.native.request('another-user','GET','/api/agent-outreach-drafts')
        for method,path in [('POST','/api/agent-keys'),('POST','/api/send-email'),('GET','https://evil.example/api/profile'),('POST','/api/agent-outreach-drafts/x/approve?sender=1')]:
            with self.assertRaises(ValueError):self.native.request('chris',method,path,{})
        with self.assertRaises(catalog.ApiError):self.agent()['psa'].request('POST','/api/agent-outreach-drafts/x/approve',body={})

    def test_password_never_sent_to_an_unapproved_host(self):
        for base in ('https://evil.example/api/agent/v1','http://psa-sales-backend.onrender.com/api/agent/v1','https://psa-sales-backend.onrender.com/api/agent/v1/../admin'):
            with self.assertRaises(ValueError):self.connect(base=base)
        self.assertEqual(self.calls,[])

    def test_expiry_and_sign_in_renewal_do_not_issue_another_agent_key(self):
        self.connect();self.assertEqual(svc.AgentApiKey.query.count(),1)
        self.storage.data['human-session.json']['chris']['expires_at']=datetime.now(timezone.utc).timestamp()-1
        with self.assertRaises(catalog.ApiError):self.native.request('chris','GET','/api/profile')
        result=self.connect(create_key=False)
        self.assertTrue(result['connected']);self.assertNotIn('one_time_key',result)
        self.assertEqual(svc.AgentApiKey.query.count(),1)
        self.native.disconnect('chris');self.assertFalse(self.native.status('chris')['connected'])
        self.assertEqual(svc.AgentApiKey.query.count(),1)

    def test_read_and_stop_from_kairos_follow_the_owner_boundary(self):
        self.connect();school=self.school('Stop Native School')
        args=dict(kind='custom',school_ids=[school.id],subject='Hello',body='Hi',confirm=True)
        draft=catalog.call_tool('psa_prepare_outreach',args,self.agent())
        self.native.request('chris','POST','/api/agent-outreach-drafts/'+draft['id']+'/approve',{'revision':1})
        queued=catalog.call_tool('psa_execute_approved_outreach',dict(draft_id=draft['id'],confirm=True),self.agent())
        cancelled=catalog.call_tool('psa_cancel_outreach',dict(batch_id=queued['batch_id'],confirm=True),self.agent())
        self.assertEqual(cancelled['status'],'cancelled')
        self.assertEqual(catalog.call_tool('psa_enrollments',{},self.agent())['items'],[])
        self.assertEqual(catalog.call_tool('psa_sequences',{},self.agent())['items'],[])
        self.assertEqual(self.fake.sent,[])

    def test_revoke_connection_blocks_queued_messages_and_forgets_local_key(self):
        self.connect();school=self.school('Revoked Native School')
        draft=catalog.call_tool('psa_prepare_outreach',dict(kind='custom',school_ids=[school.id],subject='Hi',body='Hello',confirm=True),self.agent())
        self.native.request('chris','POST','/api/agent-outreach-drafts/'+draft['id']+'/approve',{'revision':1})
        queued=catalog.call_tool('psa_execute_approved_outreach',dict(draft_id=draft['id'],confirm=True),self.agent())
        result=self.native.revoke_connection('chris')
        self.assertTrue(result['revoked']);self.assertNotIn('chris',self.connections)
        self.assertFalse(self.native.status('chris')['connected'])
        self.assertIsNotNone(svc.AgentApiKey.query.one().revoked_at)
        batch=svc.db.session.get(outreach.OutreachBatch,queued['batch_id'])
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])

    def test_failed_revoke_keeps_session_for_retry(self):
        self.connect()
        def unavailable(*args):raise catalog.ApiError('Could not reach the API')
        self.native.transport=unavailable
        with self.assertRaises(catalog.ApiError):self.native.revoke_connection('chris')
        self.assertTrue(self.native.status('chris')['connected'])
        self.assertIn('chris',self.connections)
        self.assertIsNone(svc.AgentApiKey.query.one().revoked_at)
        self.native.transport=self.transport
        self.assertTrue(self.native.revoke_connection('chris')['revoked'])

    def test_native_admin_upload_and_template_creation_keep_pdf_in_review(self):
        self.owner.admin=True;svc.db.session.commit();self.connect()
        encoded=base64.b64encode(b'%PDF-1.4\nsynthetic native test flyer\n%%EOF').decode()
        asset=self.native.upload('chris','pdf','Native flyer.pdf',encoded)
        template=self.native.request('chris','POST','/api/outreach/templates',dict(name='Native intro',kind='initial',step=0,audience='general',
            subject='Hello {school name}',body='Hi {contact name}',attachment_ids=[asset['id']]))
        school=self.school('Native PDF School')
        draft=catalog.call_tool('psa_prepare_outreach',dict(kind='initial',school_ids=[school.id],template_id=template['id'],template_revision=1,confirm=True),self.agent())
        self.assertTrue(draft['preview']['previews'][0]['attachments'])
        self.native.request('chris','POST','/api/agent-outreach-drafts/'+draft['id']+'/approve',{'revision':1})
        queued=catalog.call_tool('psa_execute_approved_outreach',dict(draft_id=draft['id'],confirm=True),self.agent())
        batch=svc.db.session.get(outreach.OutreachBatch,queued['batch_id'])
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        attachments=[part for part in self.fake.messages[0].walk() if part.get_content_disposition()=='attachment']
        self.assertEqual(attachments[0].get_payload(decode=True),base64.b64decode(encoded))

    def test_native_rep_cannot_upload_admin_assets(self):
        self.connect()
        with self.assertRaises(catalog.ApiError) as caught:
            self.native.upload('chris','pdf','No.pdf',base64.b64encode(b'%PDF-1.4\n%%EOF').decode())
        self.assertEqual(caught.exception.status,403)
        self.assertEqual(self.fake.sent,[])

    def test_production_sign_in_refuses_nonstandard_port(self):
        with self.assertRaises(ValueError):self.connect(base='https://psa-sales-backend.onrender.com:444/api/agent/v1')
        self.assertEqual(self.calls,[])

    def test_followup_authorization_and_revocation_stay_inside_kairos(self):
        self.owner.admin=True;svc.db.session.commit();self.connect()
        refs=[]
        for number,day in enumerate((4,10,17),1):
            template=self.native.request('chris','POST','/api/outreach/templates',dict(name=f'Native step {number}',kind='followup',step=number,
                audience='general',subject='Follow-up {school name}',body='Hi {contact name}'))
            refs.append(dict(day=day,template_id=template['id'],template_revision=1))
        sequence=self.native.request('chris','POST','/api/outreach/sequences',dict(name='Native follow-ups',audience='all',start_hour=9,end_hour=17,steps=refs))
        school=self.school('Native Sequence School',status='contacted');original=self.sent_email(school,1)
        svc.db.session.add(svc.SentMessage(sent_email_id=original.id,message_id='<native-sequence@example.test>',subject='Intro',kind='outreach',sent_at=original.sent_at))
        svc.db.session.commit()
        from datetime import timedelta
        from zoneinfo import ZoneInfo
        today=datetime.now(ZoneInfo('America/New_York')).date()
        settings=dict(sequence_id=sequence['id'],revision=sequence['revision'],original_ids=[original.id],mode='automatic',start_date=today.isoformat(),end_date=(today+timedelta(days=45)).isoformat())
        preview=self.native.request('chris','POST','/api/outreach/sequence-enrollments/preview',settings)
        with self.assertRaises(catalog.ApiError):
            self.native.request('chris','POST','/api/outreach/sequence-enrollments/commit',dict(review_id=preview['review_id'],settings=settings))
        result=self.native.request('chris','POST','/api/outreach/sequence-enrollments/commit',dict(review_id=preview['review_id'],settings=settings,confirm='AUTHORIZE_AUTOMATIC_SEQUENCE'))
        eid=result['enrollment_ids'][0]
        self.assertEqual(self.native.request('chris','GET','/api/outreach/sequence-enrollments')['items'][0]['id'],eid)
        self.native.request('chris','POST',f'/api/outreach/sequence-enrollments/{eid}/cancel',{})
        self.assertNotEqual(svc.db.session.get(svc.SequenceEnrollment,eid).status,'active')
        self.assertEqual(self.fake.sent,[])

    def test_campaign_review_approval_and_stop_require_no_website(self):
        self.owner.admin=True;svc.db.session.commit();self.connect()
        template=self.native.request('chris','POST','/api/outreach/templates',dict(name='Native campaign intro',kind='initial',step=0,audience='general',subject='Hi {school name}',body='Hello {contact name}'))
        school=self.school('Native Campaign School')
        from datetime import timedelta
        from zoneinfo import ZoneInfo
        today=datetime.now(ZoneInfo('America/New_York')).date()
        draft=catalog.call_tool('psa_prepare_campaign',dict(name='Native bounded campaign',school_ids=[school.id],template_id=template['id'],template_revision=1,daily_cap=10,start_date=today.isoformat(),end_date=(today+timedelta(days=40)).isoformat(),confirm=True),self.agent())
        preview=self.native.request('chris','GET','/api/outreach/campaign-plans/'+draft['id'])
        self.assertEqual(preview['preview']['rows'][0]['email'],school.email)
        approved=self.native.request('chris','POST','/api/outreach/campaign-plans/'+draft['id']+'/approve',dict(revision=draft['revision'],confirm='AUTHORIZE_CAMPAIGN'))
        self.assertEqual(approved['status'],'scheduled')
        summary=self.native.request('chris','GET','/api/outreach/campaign-plans/'+draft['id']+'/summary')
        self.assertEqual(summary['smtp_accepted'],0)
        stopped=catalog.call_tool('psa_stop_campaign',dict(plan_id=draft['id'],revision=approved['revision'],action='cancel',confirm=True),self.agent())
        self.assertEqual(stopped['status'],'cancelled')
        self.assertEqual(self.fake.sent,[])
