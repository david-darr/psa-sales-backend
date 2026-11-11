import json
from datetime import datetime, timedelta
from unittest.mock import patch
from api.tests import test_agent_workflows as agent_tests
from api.tests.test_outreach_batches import OutreachBase
from api import api as svc, outreach

BASE='/api/outreach/campaign-plans'
AGENT='/api/agent/v1/outreach/campaign-plans'


class CampaignPlanTests(OutreachBase):
    key=agent_tests.AgentWorkflowTests.key

    def setUp(self):
        super().setUp()
        clock=patch.object(svc,'utc_now',return_value=datetime(2026,11,9,15))
        self.time=clock.start();self.addCleanup(clock.stop)
        flag=patch.dict('os.environ',{'CAMPAIGN_AUTOMATION_ENABLED':'true'});flag.start();self.addCleanup(flag.stop)
        self.sync_ready(self.owner)
        self.key_data,self.headers=self.key(capabilities=['outreach:read','outreach:prepare','outreach:send'])

    def template(self,**changes):
        values=dict(name='Campaign intro',kind='initial',step=0,audience='general',subject='Hello {school name}',body='Hi {contact name}')
        values.update(changes)
        response=self.client.post('/api/outreach/templates',headers=self.auth(self.admin),json=values)
        self.assertEqual(response.status_code,201,response.get_json());return response.get_json()

    def prepare(self,schools=None,**changes):
        schools=schools or [self.school('Campaign School')];template=self.template()
        settings=dict(name='Winter campaign',school_ids=[s.id for s in schools],template_id=template['id'],template_revision=1,audience='all',daily_cap=10,start_date='2026-11-09',end_date='2026-12-20')
        settings.update(changes)
        response=self.client.post(AGENT,headers=self.headers,json=settings)
        self.assertEqual(response.status_code,201,response.get_json());return response.get_json()

    def action(self,plan,action,**data):
        return self.client.post(BASE+'/'+plan['id']+'/'+action,headers=self.auth(self.owner),json=dict(revision=plan['revision'],**data))

    def approve(self,plan):
        result=self.action(plan,'approve',confirm='AUTHORIZE_CAMPAIGN')
        self.assertEqual(result.status_code,200,result.get_json());return result.get_json()

    def send_batches(self):
        for batch in outreach.OutreachBatch.query.filter_by(status='queued').all():outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)

    def test_prepare_never_sends_and_agent_cannot_approve(self):
        plan=self.prepare()
        self.assertEqual(plan['status'],'awaiting');self.assertEqual(svc.schedule_campaigns(),0)
        self.assertEqual(self.action(plan,'approve').status_code,409)
        self.assertEqual(self.client.post(BASE+'/'+plan['id']+'/approve',headers=self.headers,json=dict(revision=1,confirm='AUTHORIZE_CAMPAIGN')).status_code,422)
        self.assertEqual(self.client.post(AGENT+'/'+plan['id']+'/approve',headers=self.headers,json={}).status_code,404)
        self.assertEqual(self.fake.sent,[])

    def test_fixed_scope_idempotent_worker_and_cumulative_summary(self):
        school=self.school('Fixed scope');plan=self.approve(self.prepare([school]))
        self.school('New matching school')
        self.assertEqual(svc.schedule_campaigns(),1);self.assertEqual(svc.schedule_campaigns(),0)
        self.send_batches();self.assertEqual(svc.schedule_campaigns(),0)
        self.assertEqual(self.fake.sent,[school.email])
        row=svc.db.session.get(svc.CampaignPlan,plan['id']);self.assertEqual(row.status,'completed')
        summary=self.client.get(BASE+'/'+plan['id']+'/summary',headers=self.auth(self.owner)).get_json()
        self.assertEqual(summary['smtp_accepted'],1);self.assertIn('not confirmed',summary['delivery_note'])
        self.client.get(BASE+'/'+plan['id']+'/summary',headers=self.auth(self.owner))
        self.assertEqual(svc.CampaignSummary.query.count(),1)

    def test_preview_change_expiry_and_owner_boundaries(self):
        school=self.school('Changed contact');plan=self.prepare([school])
        school.contact_name='Changed';svc.db.session.commit()
        self.assertEqual(self.action(plan,'approve',confirm='AUTHORIZE_CAMPAIGN').status_code,409)
        for actor in (self.other,self.admin):
            self.assertEqual(self.client.get(BASE+'/'+plan['id'],headers=self.auth(actor)).status_code,404)
            self.assertEqual(self.client.post(BASE+'/'+plan['id']+'/approve',headers=self.auth(actor),json=dict(revision=1,confirm='AUTHORIZE_CAMPAIGN')).status_code,404)
        self.time.return_value+=timedelta(minutes=16)
        self.assertEqual(self.action(plan,'approve',confirm='AUTHORIZE_CAMPAIGN').status_code,409)

    def test_changed_template_blocks_queued_mail_and_cannot_auto_resume(self):
        plan=self.approve(self.prepare());self.assertEqual(svc.schedule_campaigns(),1)
        template=svc.db.session.get(svc.MailTemplate,plan['settings']['template_id']);template.revision+=1;svc.db.session.commit()
        self.send_batches();self.assertEqual(self.fake.sent,[])
        svc.schedule_campaigns()
        current=self.client.get(BASE+'/'+plan['id'],headers=self.auth(self.owner)).get_json()
        self.assertEqual(current['status'],'paused');self.assertEqual(self.action(current,'resume').status_code,409)

    def test_pause_resume_and_cancel_are_revision_bound(self):
        plan=self.approve(self.prepare());svc.schedule_campaigns()
        paused=self.action(plan,'pause');self.assertEqual(paused.status_code,200);paused=paused.get_json()
        self.send_batches();self.assertEqual(self.fake.sent,[])
        self.assertEqual(self.action(plan,'resume').status_code,409)
        resumed=self.action(paused,'resume');self.assertEqual(resumed.status_code,200,resumed.get_json())
        self.send_batches();self.assertEqual(len(self.fake.sent),1)
        cancelled=self.action(resumed.get_json(),'cancel');self.assertEqual(cancelled.status_code,200)
        self.assertEqual(self.action(cancelled.get_json(),'resume').status_code,409)

    def test_caps_window_expiry_and_kill_switch(self):
        plan=self.approve(self.prepare([self.school('Cap One'),self.school('Cap Two')],daily_cap=1))
        self.assertEqual(svc.schedule_campaigns(),1);self.send_batches()
        self.assertEqual(svc.schedule_campaigns(),0);self.assertEqual(len(self.fake.sent),1)
        self.time.return_value=datetime(2026,11,10,3);self.assertEqual(svc.schedule_campaigns(),0)
        self.time.return_value=datetime(2026,11,10,15)
        with patch.dict('os.environ',{'CAMPAIGN_AUTOMATION_ENABLED':'false'}):self.assertEqual(svc.schedule_campaigns(),0)
        self.assertEqual(svc.schedule_campaigns(),1)
        self.time.return_value=datetime(2027,1,1,15);self.send_batches()
        self.assertEqual(len(self.fake.sent),1)

    def test_revocation_and_suppression_remove_recipients(self):
        school=self.school('Suppressed');plan=self.approve(self.prepare([school]))
        contact=svc.Contact.query.filter_by(email=school.email).one();contact.do_not_contact=True;svc.db.session.commit()
        self.assertEqual(svc.schedule_campaigns(),0);self.assertEqual(svc.CampaignMember.query.one().status,'skipped')
        second=self.approve(self.prepare([self.school('Revoked')]))
        key=svc.db.session.get(svc.AgentApiKey,self.key_data['id']);key.revoked_at=svc.utc_now();svc.db.session.commit()
        self.assertEqual(svc.schedule_campaigns(),0)
        self.assertEqual(svc.db.session.get(svc.CampaignPlan,second['id']).status,'paused')

    def test_agent_stop_accepts_no_resume_or_scope_override(self):
        plan=self.approve(self.prepare())
        for action in ('approve','resume'):
            self.assertEqual(self.client.post(AGENT+'/'+plan['id']+'/stop',headers=self.headers,json=dict(revision=plan['revision'],action=action)).status_code,400)
        result=self.client.post(AGENT+'/'+plan['id']+'/stop',headers=self.headers,json=dict(revision=plan['revision'],action='pause'))
        self.assertEqual(result.status_code,200,result.get_json());self.assertEqual(result.get_json()['status'],'paused')

    def test_detected_bounce_blocks_a_different_queued_batch(self):
        schools=[self.school(f'Bounce stop {i}') for i in range(4)]
        plan=self.approve(self.prepare(schools))
        self.assertEqual(svc.schedule_campaigns(2),2)
        self.assertEqual(svc.schedule_campaigns(2),2)
        # Feedback can arrive outside the sending worker, after an earlier send.
        svc.record_mail_signal(schools[0].email,'hard_bounce','campaign-fixture-bounce','Synthetic test signal',actor_id=self.owner.id)
        svc.db.session.commit()
        self.send_batches();self.assertEqual(self.fake.sent,[])
        svc.schedule_campaigns()
        row=svc.db.session.get(svc.CampaignPlan,plan['id'])
        self.assertEqual(row.status,'paused');self.assertIn('feedback',row.reason)

    def test_partial_smtp_uncertainty_never_resends_or_advances_campaign(self):
        schools=[self.school('Uncertain one'),self.school('Uncertain two')]
        plan=self.approve(self.prepare(schools))
        svc.schedule_campaigns();self.fake.disconnect_once_for.add(schools[0].email)
        self.send_batches();svc.schedule_campaigns();self.send_batches()
        self.assertEqual(self.fake.sent,[])
        self.assertEqual(outreach.OutreachAttempt.query.count(),1)
        self.assertEqual(svc.db.session.get(svc.CampaignPlan,plan['id']).status,'paused')

    def test_material_edits_need_new_review_and_sender_change_stops_queue(self):
        plan=self.prepare()
        settings={**plan['settings'],'daily_cap':1}
        refreshed=self.action(plan,'refresh',settings=settings)
        self.assertEqual(refreshed.status_code,200,refreshed.get_json())
        self.assertEqual(self.action(plan,'approve',confirm='AUTHORIZE_CAMPAIGN').status_code,409)
        plan=self.approve(refreshed.get_json());svc.schedule_campaigns()
        self.owner.email='different-sender@example.test';svc.db.session.commit()
        self.send_batches();self.assertEqual(self.fake.sent,[])
        self.assertEqual(self.action(plan,'refresh',settings=settings).status_code,409)

    def test_large_preview_and_fair_scheduling_between_campaigns(self):
        schools=[self.school(f'Large campaign {i}') for i in range(110)]
        first=self.approve(self.prepare(schools))
        self.assertEqual(len(first['preview']['rows']),110)
        second=self.approve(self.prepare([self.school('Other campaign')]))
        self.assertEqual(svc.schedule_campaigns(1),1)
        self.assertEqual(svc.schedule_campaigns(1),1)
        self.assertEqual(svc.CampaignMember.query.filter_by(plan_id=second['id'],status='queued').count(),1)

    def test_cancel_releases_definitely_unsent_reservations(self):
        school=self.school('Cancelled unsent');plan=self.approve(self.prepare([school]))
        svc.schedule_campaigns()
        result=self.action(plan,'cancel');self.assertEqual(result.status_code,200)
        self.assertEqual(outreach.OutreachRecipient.query.one().status,'cancelled')
        replacement=self.prepare([school])
        self.assertTrue(replacement['preview']['rows'][0]['eligible'])
        self.assertEqual(self.fake.sent,[])

    def test_stage_stop_persists_if_stage_is_changed_back_before_dispatch(self):
        school=self.school('Sticky stage stop');plan=self.approve(self.prepare([school]))
        svc.schedule_campaigns()
        school.status='replied';svc.db.session.commit()
        school.status='pending';svc.db.session.commit()
        self.send_batches();svc.schedule_campaigns()
        self.assertEqual(self.fake.sent,[])
        self.assertEqual(svc.CampaignMember.query.one().status,'skipped')

    def test_sequence_enrolls_only_after_recorded_intro_and_stays_threaded(self):
        refs=[]
        for number,day in enumerate((4,10,17),1):
            template=self.template(name=f'Follow-up {number}',kind='followup',step=number)
            refs.append(dict(day=day,template_id=template['id'],template_revision=1))
        seq=self.client.post('/api/outreach/sequences',headers=self.auth(self.admin),json=dict(name='Winter sequence',audience='all',start_hour=9,end_hour=17,steps=refs)).get_json()
        plan=self.approve(self.prepare(sequence_id=seq['id'],sequence_revision=1))
        svc.schedule_campaigns();self.assertEqual(svc.SequenceEnrollment.query.count(),0)
        self.send_batches();svc.schedule_campaigns()
        enrollment=svc.SequenceEnrollment.query.one();self.assertEqual(enrollment.mode,'automatic')
        self.assertEqual(svc.SequenceStep.query.count(),3)
        self.assertTrue(svc.db.session.get(svc.SentEmail,enrollment.original_id).sequence_managed)
        first=svc.SequenceStep.query.filter_by(number=1).one();self.time.return_value=first.due_at
        with patch.object(svc,'sync_user_mailbox',return_value={'ready':True}):
            state=svc.db.session.get(svc.MailSyncState,self.owner.id);state.last_success_at=svc.utc_now();svc.db.session.commit()
            self.assertEqual(svc.schedule_sequences(),1);self.send_batches()
        self.assertEqual(len(self.fake.sent),2);self.assertTrue(self.fake.messages[-1]['In-Reply-To'])
        current=self.client.get(BASE+'/'+plan['id'],headers=self.auth(self.owner)).get_json()
        self.action(current,'cancel')
        self.time.return_value+=timedelta(days=30)
        self.assertEqual(svc.schedule_sequences(),0)

    def test_school_specific_stop_does_not_stop_sister_school_campaign(self):
        first=self.school('PTA school A');other=self.school('PTA school B')
        other.email=first.email;svc.db.session.commit()
        a=self.approve(self.prepare([first]));b=self.approve(self.prepare([other]))
        link=svc.SchoolContact.query.filter_by(school_id=first.id).first()
        link.do_not_contact=True;link.suppression_reason='School A only';link.version+=1;svc.db.session.commit()
        svc.schedule_campaigns();self.send_batches()
        self.assertEqual(self.fake.sent,[other.email])
        self.assertEqual(svc.CampaignMember.query.filter_by(plan_id=a['id']).one().status,'skipped')
