from datetime import datetime
from api.tests.test_outreach_batches import OutreachBase
from api import api as svc


class RecordQualityTests(OutreachBase):
    def pair(self):return self.school('Maple Academy'),self.school('Maple Academy')
    def preview(self,a,b,user=None):return self.client.post('/api/crm/schools/merge/preview',headers=self.auth(user or self.admin),json={'source_id':a.id,'target_id':b.id})
    def commit(self,a,b,token):return self.client.post('/api/crm/schools/merge/commit',headers=self.auth(self.admin),json={'source_id':a.id,'target_id':b.id,'review_token':token})
    def test_duplicate_warning_and_history_preserving_reviewed_merge(self):
        a,b=self.pair();aid,bid=a.id,b.id;a.notes='Source notes';svc.db.session.add(svc.SchoolActivity(sales_school_id=a.id,actor_id=self.owner.id,kind='call',detail='Called owner'))
        svc.db.session.add(svc.SalesTask(user_id=self.owner.id,school_id=a.id,title='Call back',priority='low'))
        mail=self.sent_email(a,2);mailid=mail.id;svc.db.session.commit()
        links=svc.SchoolContact.query.filter_by(contact_id=svc.Contact.query.filter_by(email=a.email).one().id).all()
        links[0].do_not_contact=True;links[0].suppression_reason='School stop';svc.db.session.commit()
        matches=self.client.get(f'/api/crm/schools/{a.id}/duplicates',headers=self.auth(self.admin)).get_json()
        self.assertEqual(matches['items'][0]['id'],b.id)
        response=self.preview(a,b);self.assertEqual(response.status_code,200,response.get_json())
        token=response.get_json()['review_token'];result=self.commit(a,b,token)
        self.assertEqual(result.status_code,200,result.get_json());svc.db.session.expire_all()
        self.assertIsNone(svc.SalesSchool.query.filter_by(id=aid).first())
        self.assertEqual(svc.SentEmail.query.filter_by(id=mailid).one().sales_school_id,b.id)
        self.assertEqual(svc.SalesTask.query.one().school_id,b.id)
        self.assertTrue(svc.SchoolContact.query.filter_by(school_id=b.id).one().do_not_contact)
        self.assertIn('Source notes',svc.SalesSchool.query.filter_by(id=b.id).one().notes)
        self.assertEqual(self.client.post('/api/crm/schools/merge/commit',headers=self.auth(self.admin),json={'source_id':aid,'target_id':bid,'review_token':token}).status_code,404)
    def test_review_staleness_roles_and_workspace_boundary(self):
        a,b=self.pair()
        self.assertEqual(self.preview(a,b,self.owner).status_code,403)
        token=self.preview(a,b).get_json()['review_token'];b.notes='Changed';svc.db.session.commit()
        self.assertEqual(self.commit(a,b,token).status_code,409)
        b.sales_workspace='business';svc.db.session.commit()
        self.assertEqual(self.preview(a,b).status_code,404)
    def test_ai_merge_uses_the_same_review_and_admin_boundary(self):
        from api.tests import test_agent_workflows as fixture
        a,b=self.pair()
        _,headers=fixture.AgentWorkflowTests.key(self,user=self.admin,scope='write')
        path='/api/agent/v1/operations/'
        body=dict(source_id=a.id,target_id=b.id)
        review=self.client.post(path+'psa_preview_record_merge',headers=headers,json=body)
        self.assertEqual(review.status_code,200,review.get_json())
        result=self.client.post(path+'psa_commit_record_merge',headers=headers,json={**body,'review_token':review.get_json()['review_token']})
        self.assertEqual(result.status_code,200,result.get_json())

    def test_ownership_and_active_sending_block_merge(self):
        a,b=self.pair();b.user_id=self.other.id;svc.db.session.commit()
        self.assertEqual(self.preview(a,b).status_code,409)
        b.user_id=self.owner.id
        batch=svc.OutreachBatch(user_id=self.owner.id,kind='custom',status='queued')
        svc.db.session.add(batch);svc.db.session.flush()
        svc.db.session.add(svc.OutreachRecipient(batch_id=batch.id,school_id=a.id,school_name=a.school_name,email=a.email,status='queued'))
        svc.db.session.commit();self.assertEqual(self.preview(a,b).status_code,409)


class ReportingTests(OutreachBase):
    def add_message(self,owner,area='school',audience='pta_pto',responded=False,kind='initial'):
        school=self.school('Report '+str(owner.id)+str(svc.SentEmail.query.count()),owner=owner,sales_workspace=area)
        sent=self.sent_email(school,0,owner=owner);sent.responded=responded
        batch=svc.OutreachBatch(user_id=owner.id,sales_workspace=area,kind=kind,status='done',audience=audience,template_snapshot='{"id":7,"name":"Intro","audience":"general"}')
        svc.db.session.add(batch);svc.db.session.flush()
        svc.db.session.add(svc.OutreachRecipient(batch_id=batch.id,school_id=school.id,school_name=school.school_name,email=school.email,status='sent',sent_email_id=sent.id,sent_at=svc.utc_now()))
        svc.db.session.commit()
    def test_rates_use_distinct_conversations_and_preserve_role_and_area(self):
        self.add_message(self.owner,responded=True);self.add_message(self.owner);self.add_message(self.other);self.add_message(self.owner,area='business')
        own=self.client.get('/api/outreach/reporting',headers=self.auth(self.owner)).get_json()
        self.assertEqual(own['totals']['sent'],2)
        self.assertEqual(own['by_audience'][0]['reply_rate'],50)
        team=self.client.get('/api/outreach/reporting',headers=self.auth(self.admin)).get_json()
        self.assertEqual(team['totals']['sent'],3)
        business=self.client.get('/api/outreach/reporting',headers={**self.auth(self.admin),'X-PSA-Workspace':'business'}).get_json()
        self.assertEqual(business['totals']['sent'],1)
        self.assertEqual(self.client.get('/api/outreach/reporting?start=invalid',headers=self.auth(self.admin)).status_code,400)
    def test_self_test_not_counted(self):
        self.add_message(self.owner,kind='test')
        self.assertEqual(self.client.get('/api/outreach/reporting',headers=self.auth(self.owner)).get_json()['totals'],{})


class PreviewEncodingTests(OutreachBase):
    def test_middle_dot_survives_template_save_and_message_preview(self):
        school=self.school('Encoding fixture')
        subject='Intro '+chr(183)+' {school name}'
        created=self.client.post('/api/outreach/templates',headers=self.auth(self.admin),json=dict(name='Encoding test',kind='initial',step=0,audience='general',subject=subject,body='Hello {contact name}',attachment_ids=[]))
        self.assertEqual(created.status_code,201,created.get_json())
        preview=self.client.post('/api/email-preview',headers=self.auth(self.owner),json=dict(school_ids=[school.id],kind='initial',template_id=created.get_json()['id'],template_revision=1,contact_mode=True,audience='all'))
        self.assertEqual(preview.status_code,200,preview.get_json())
        text=preview.get_json()['previews'][0]['subject']
        self.assertIn(chr(183),text)
        self.assertNotIn(chr(194)+chr(183),text)
