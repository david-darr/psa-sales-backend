import json
import io
from datetime import datetime, timedelta
from unittest.mock import patch
from api.tests.test_outreach_batches import OutreachBase
from api import api as svc, outreach
from api.sequences import nominal_due, next_window


class SequenceTests(OutreachBase):
    def setUp(self):
        super().setUp()
        self.clock = patch.object(svc, 'utc_now', return_value=datetime(2026,11,5,15))
        self.time = self.clock.start(); self.addCleanup(self.clock.stop)
        self.sync_ready(self.owner)
        def fresh(user):
            state = svc.db.session.get(svc.MailSyncState,user.id)
            if not state: state=svc.MailSyncState(user_id=user.id);svc.db.session.add(state)
            state.last_success_at=svc.utc_now(); state.pending_count=0;state.last_error=None
            svc.db.session.commit(); return {'ready':True}
        sync=patch.object(svc,'sync_user_mailbox',side_effect=fresh);sync.start();self.addCleanup(sync.stop)

    def definition(self):
        refs=[]
        for step in range(1,4):
            res=self.client.post('/api/outreach/templates',headers=self.auth(self.admin),json=dict(
                name=f'Step {step}',kind='followup',step=step,audience='general',subject=f'Step {step} for {{school name}}',body='Hello {contact name} from {my name}'))
            self.assertEqual(res.status_code,201,res.get_json())
            refs.append(dict(template_id=res.get_json()['id'],template_revision=1,day=[4,10,17][step-1]))
        body=dict(name='Season follow-ups',audience='all',start_hour=9,end_hour=17,steps=refs)
        res=self.client.post('/api/outreach/sequences',headers=self.auth(self.admin),json=body)
        self.assertEqual(res.status_code,201,res.get_json())
        return res.get_json(),body

    def original(self, days=1):
        school=self.school('Sequence School',status='contacted')
        record=self.sent_email(school,days)
        svc.db.session.add(svc.SentMessage(sent_email_id=record.id,message_id=f'<intro-{record.id}@example.test>',subject='Intro',kind='outreach',sent_at=record.sent_at))
        svc.db.session.commit();return school,record

    def settings(self, sequence, original, **changes):
        return dict(sequence_id=sequence['id'],revision=sequence['revision'],original_ids=[original.id],mode='review',
                    start_date='2026-11-05',end_date='2026-12-20',**changes)

    def enroll(self, settings):
        preview=self.client.post('/api/outreach/sequence-enrollments/preview',headers=self.auth(self.owner),json=settings)
        self.assertEqual(preview.status_code,200,preview.get_json())
        body=dict(review_id=preview.get_json()['review_id'],settings=settings)
        if settings['mode']=='automatic':body['confirm']='AUTHORIZE_AUTOMATIC_SEQUENCE'
        result=self.client.post('/api/outreach/sequence-enrollments/commit',headers=self.auth(self.owner),json=body)
        self.assertEqual(result.status_code,201,result.get_json())
        return svc.db.session.get(svc.SequenceEnrollment,result.get_json()['enrollment_ids'][0]),body

    def move_to_due(self,enrollment,number=1):
        step=svc.SequenceStep.query.filter_by(enrollment_id=enrollment.id,number=number).one()
        self.time.return_value=step.due_at;return step

    def approve(self,step):
        path=f'/api/outreach/sequence-steps/{step.id}'
        review=self.client.post(path+'/preview',headers=self.auth(self.owner),json={})
        self.assertEqual(review.status_code,200,review.get_json())
        result=self.client.post(path+'/approve',headers=self.auth(self.owner),json=dict(preview_token=review.get_json()['preview_token']))
        self.assertEqual(result.status_code,200,result.get_json())

    def test_exact_days_weekends_and_dst(self):
        self.assertEqual(nominal_due(datetime(2026,11,4,15),4),datetime(2026,11,9,15))
        self.assertEqual(nominal_due(datetime(2026,3,6,15),4),datetime(2026,3,10,14))
        self.assertEqual(nominal_due(datetime(2026,10,30,14),4),datetime(2026,11,3,15))
        self.assertEqual(next_window(datetime(2026,11,6,23)),datetime(2026,11,9,14))

    def test_review_is_default_and_never_sends_without_step_approval(self):
        seq,_=self.definition();school,original=self.original()
        enrollment,_=self.enroll(self.settings(seq,original))
        listing=self.client.get('/api/outreach/sequence-enrollments',headers=self.auth(self.owner))
        self.assertEqual(listing.status_code,200,listing.get_json())
        self.assertEqual(len(listing.get_json()['items'][0]['steps']),3)
        step=self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),0)
        self.assertEqual(self.fake.sent,[])
        self.approve(step)
        self.assertEqual(svc.schedule_sequences(),1)
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence').one()
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        svc.db.session.expire_all()
        self.assertEqual(self.fake.sent,[school.email])
        self.assertEqual(svc.db.session.get(svc.SequenceStep,step.id).status,'sent')
        self.assertEqual(self.fake.messages[0]['In-Reply-To'],f'<intro-{original.id}@example.test>')
        self.assertIn(f'<intro-{original.id}@example.test>',self.fake.messages[0]['References'])
        self.assertEqual(original.followup_count,0)
        self.assertTrue(original.sequence_managed)
        self.assertIsNotNone(svc.followup_eligibility_error(original))
        self.assertEqual(outreach.due_followup_school_ids(self.owner),[])

    def test_automatic_mode_needs_explicit_confirmation_and_commit_is_idempotent(self):
        seq,_=self.definition();_,original=self.original()
        settings=self.settings(seq,original);settings['mode']='automatic'
        review=self.client.post('/api/outreach/sequence-enrollments/preview',headers=self.auth(self.owner),json=settings).get_json()
        body=dict(review_id=review['review_id'],settings=settings)
        self.assertEqual(self.client.post('/api/outreach/sequence-enrollments/commit',headers=self.auth(self.owner),json=body).status_code,409)
        body['confirm']='AUTHORIZE_AUTOMATIC_SEQUENCE'
        first=self.client.post('/api/outreach/sequence-enrollments/commit',headers=self.auth(self.owner),json=body)
        second=self.client.post('/api/outreach/sequence-enrollments/commit',headers=self.auth(self.owner),json=body)
        self.assertEqual(first.get_json(),second.get_json())
        enrollment=svc.SequenceEnrollment.query.one();self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),1)
        self.assertEqual(svc.schedule_sequences(),0)

    def test_school_stage_reset_never_revives_sequence(self):
        seq,_=self.definition();school,original=self.original()
        settings=self.settings(seq,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings)
        school.status='meeting';svc.db.session.commit()
        school.status='contacted';svc.db.session.commit();svc.db.session.expire_all()
        self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),0)
        self.assertEqual(svc.SequenceEnrollment.query.one().status,'paused')
        self.assertTrue(all(s.status=='stopped' for s in svc.SequenceStep.query.all()))

    def test_changed_template_invalidates_enrollment_review_and_active_approval(self):
        seq,definition=self.definition();_,original=self.original()
        settings=self.settings(seq,original)
        review=self.client.post('/api/outreach/sequence-enrollments/preview',headers=self.auth(self.owner),json=settings).get_json()
        template=svc.db.session.get(svc.MailTemplate,definition['steps'][0]['template_id']);template.revision+=1;svc.db.session.commit()
        body=dict(review_id=review['review_id'],settings=settings)
        result=self.client.post('/api/outreach/sequence-enrollments/commit',headers=self.auth(self.owner),json=body)
        self.assertEqual(result.status_code,409)
        self.assertEqual(self.fake.sent,[])

    def test_pause_revoke_and_owner_change_before_dispatch(self):
        seq,_=self.definition();school,original=self.original()
        settings=self.settings(seq,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings);self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),1)
        result=self.client.post(f'/api/outreach/sequence-enrollments/{enrollment.id}/cancel',headers=self.auth(self.owner),json={})
        self.assertEqual(result.status_code,200)
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence').one()
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])

    def test_no_catchup_burst_and_true_three_step_thread(self):
        seq,_=self.definition();school,original=self.original(days=20)
        settings=self.settings(seq,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings)
        for number in range(1,4):
            step=self.move_to_due(enrollment,number)
            self.assertEqual(svc.schedule_sequences(),1)
            batch=outreach.OutreachBatch.query.filter_by(kind='sequence',status='queued').one()
            outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
            svc.db.session.expire_all()
            self.assertEqual(len(self.fake.sent),number)
            self.assertEqual(svc.schedule_sequences(),0)
            if number<3:
                following=svc.SequenceStep.query.filter_by(enrollment_id=enrollment.id,number=number+1).one()
                self.assertGreater(following.due_at,step.sent_at+timedelta(hours=12))
        self.assertEqual(svc.SequenceEnrollment.query.one().status,'done')
        self.assertEqual(svc.SentMessage.query.filter_by(kind='sequence_followup').count(),3)
        self.assertIn(self.fake.messages[0]['Message-ID'],self.fake.messages[2]['References'])

    def test_sync_failure_and_closed_window_send_nothing(self):
        seq,_=self.definition();_,original=self.original()
        settings=self.settings(seq,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings);step=self.move_to_due(enrollment)
        self.time.return_value=step.due_at.replace(hour=23)
        self.assertEqual(svc.schedule_sequences(),0)
        self.time.return_value=step.due_at
        with patch.object(svc,'sync_user_mailbox',return_value={'ready':False}):self.assertEqual(svc.schedule_sequences(),0)
        self.assertEqual(svc.SequenceEnrollment.query.one().status,'paused')
        self.assertEqual(self.fake.sent,[])

    def test_worker_recovers_unsent_queue_but_never_retries_inflight(self):
        school=self.school('Recovery')
        batch_id=self.create_batch(self.owner,school_ids=[school.id],kind='initial').get_json()['batch_id']
        batch=svc.db.session.get(outreach.OutreachBatch,batch_id)
        batch.lease_owner='dead-worker';batch.lease_until=svc.utc_now()-timedelta(seconds=1)
        svc.db.session.commit();svc.recover_outreach_leases()
        self.assertEqual(svc.db.session.get(outreach.OutreachBatch,batch_id).status,'queued')
        batch.status='sending';batch.lease_owner='dead-worker';batch.lease_until=svc.utc_now()-timedelta(seconds=1)
        recipient=outreach.OutreachRecipient.query.filter_by(batch_id=batch_id).one();recipient.status='sending'
        svc.db.session.commit();svc.recover_outreach_leases()
        self.assertEqual(svc.db.session.get(outreach.OutreachBatch,batch_id).status,'paused')
        self.assertEqual(svc.db.session.get(outreach.OutreachRecipient,recipient.id).status,'unconfirmed')
        self.assertEqual(self.fake.sent,[])

    def test_queue_waiting_for_business_window_is_not_stalled(self):
        batch=outreach.OutreachBatch(status='queued',available_at=svc.utc_now()+timedelta(days=1),heartbeat_at=svc.utc_now()-timedelta(hours=3))
        self.assertEqual(outreach.effective_status(batch),'queued')

    def test_durable_worker_processes_queue_and_reports_heartbeat(self):
        school=self.school('Durable')
        address,headers=school.email,self.auth(self.owner)
        self.create_batch(self.owner,school_ids=[school.id],kind='initial')
        self.assertFalse(self.client.get('/api/outreach/worker',headers=self.auth(self.owner)).get_json()['online'])
        svc.run_outreach_cycle('test-worker',max_jobs=1)
        self.assertEqual(self.fake.sent,[address])
        self.assertTrue(self.client.get('/api/outreach/worker',headers=headers).get_json()['online'])

    def test_unauthorized_users_cannot_create_or_revoke_other_mailboxes(self):
        self.assertEqual(self.client.post('/api/outreach/sequences',headers=self.auth(self.owner),json={}).status_code,403)
        seq,_=self.definition();_,original=self.original();enrollment,_=self.enroll(self.settings(seq,original))
        self.assertEqual(self.client.post(f'/api/outreach/sequence-enrollments/{enrollment.id}/cancel',headers=self.auth(self.other),json={}).status_code,404)
        self.assertEqual(self.client.get('/api/outreach/sequence-enrollments',headers=self.auth(self.other)).get_json()['items'],[])

    def test_expired_step_approval_and_authorization_send_nothing(self):
        seq,_=self.definition();_,original=self.original()
        enrollment,_=self.enroll(self.settings(seq,original));step=self.move_to_due(enrollment)
        self.approve(step);self.time.return_value+=timedelta(minutes=16)
        self.assertEqual(svc.schedule_sequences(),0)
        self.time.return_value=enrollment.ends_at+timedelta(minutes=1)
        self.assertEqual(svc.schedule_sequences(),0)
        self.assertEqual(self.fake.sent,[])

    def test_owner_change_after_queue_blocks_smtp(self):
        seq,_=self.definition();school,original=self.original()
        settings=self.settings(seq,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings);self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),1)
        school.user_id=self.other.id;svc.db.session.commit()
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence').one()
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])
        self.assertEqual(svc.SequenceEnrollment.query.one().status,'paused')

    def test_reply_after_queue_blocks_smtp(self):
        seq,_=self.definition();_,original=self.original()
        settings=self.settings(seq,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings);self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),1)
        original.responded=True;svc.db.session.commit()
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence').one()
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        self.assertEqual(self.fake.sent,[])

    def test_version_edit_pauses_and_preserves_history(self):
        seq,definition=self.definition();_,original=self.original()
        enrollment,_=self.enroll(self.settings(seq,original))
        result=self.client.put(f"/api/outreach/sequences/{seq['id']}",headers=self.auth(self.admin),json={**definition,'revision':1,'name':'Revised season'})
        self.assertEqual(result.status_code,200,result.get_json())
        self.assertEqual(result.get_json()['revision'],2)
        self.assertEqual(svc.db.session.get(svc.SequenceEnrollment,enrollment.id).status,'paused')
        self.assertEqual(self.client.put(f"/api/outreach/sequences/{seq['id']}",headers=self.auth(self.admin),json={**definition,'revision':1}).status_code,409)
        history=self.client.get(f"/api/outreach/sequences/{seq['id']}/versions",headers=self.auth(self.admin)).get_json()['items']
        self.assertEqual([r['revision'] for r in history],[2,1])

    def test_template_catalog_pdf_is_included_unchanged(self):
        pdf=b'%PDF-1.4\nSequence catalog fixture'
        upload=self.client.post('/api/outreach/template-assets',headers=self.auth(self.admin),data={'file':(io.BytesIO(pdf),'sequence.pdf')})
        self.assertEqual(upload.status_code,201,upload.get_json())
        seq,definition=self.definition()
        template=seq['steps'][0]['template']
        changed=self.client.put(f"/api/outreach/templates/{template['id']}",headers=self.auth(self.admin),json={
            **template,'attachment_ids':[upload.get_json()['id']]})
        self.assertEqual(changed.status_code,200,changed.get_json())
        definition['steps'][0]['template_revision']=2
        revised=self.client.put(f"/api/outreach/sequences/{seq['id']}",headers=self.auth(self.admin),json={**definition,'revision':1}).get_json()
        _,original=self.original();settings=self.settings(revised,original);settings['mode']='automatic'
        enrollment,_=self.enroll(settings);self.move_to_due(enrollment)
        self.assertEqual(svc.schedule_sequences(),1)
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence').one()
        outreach.run_batch(svc.app,batch.id,batch.worker_token,delay=0)
        files=[p for p in self.fake.messages[0].walk() if p.get_content_disposition()=='attachment']
        self.assertEqual([p.get_payload(decode=True) for p in files],[pdf])
