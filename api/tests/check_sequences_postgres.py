"""Guarded, destructive local PostgreSQL / two-worker fake-SMTP check."""
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import text
from sqlalchemy.engine import make_url

url=os.environ.get('SEQUENCE_TEST_DATABASE_URL','')
parsed=make_url(url)
if parsed.host not in ('127.0.0.1','localhost') or parsed.database!='psa_sequence_test':
    raise SystemExit('Refusing: supply a disposable loopback database named psa_sequence_test')
os.environ['LOADTEST_DATABASE_URL']=url
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from api.tests import load_outreach as harness
from api import api as svc, outreach
app,db,smtp=svc.app,svc.db,harness.smtp
app.config['TESTING']=True
os.environ['OUTREACH_SEND_DELAY']='0'
clock=patch.object(svc,'utc_now',return_value=datetime(2026,11,5,15));tick=clock.start()
new={'mail_sequences','mail_sequence_versions','mail_sequence_enrollments','mail_sequence_steps','mail_sequence_reviews','outreach_worker_heartbeats'}
with app.app_context():
    engine=db.engine
    with engine.begin() as connection:connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
    db.metadata.create_all(engine,tables=[table for name,table in db.metadata.tables.items() if name not in new])
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE sent_emails DROP COLUMN sequence_managed'))
        for column in ('lease_owner','lease_until','available_at'):connection.execute(text(f'ALTER TABLE outreach_batches DROP COLUMN {column}'))
        for role in ('anon','authenticated'):
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
    migration=(Path(__file__).resolve().parents[1]/'migrations/20261105_durable_sequences.sql').read_text()
    for _ in range(2):
        raw=engine.raw_connection()
        try:
            with raw.cursor() as cursor:cursor.execute(migration)
            raw.commit()
        finally:raw.close()
    for table in new:
        assert db.session.execute(text('SELECT relrowsecurity FROM pg_class WHERE relname=:t'),dict(t=table)).scalar()
        for role in ('anon','authenticated'):
            for permission in ('SELECT','INSERT','UPDATE','DELETE'):
                assert not db.session.execute(text('SELECT has_table_privilege(:r,:t,:p)'),dict(r=role,t=table,p=permission)).scalar()
    user=svc.User(name='Sequence Rep',email='sequence@example.test',admin=True,password_hash='x',email_password=svc.encrypt_password('fake-only'))
    db.session.add(user);db.session.commit();uid=user.id
    headers={'Authorization':'Bearer '+svc.create_access_token(identity=str(uid))}
    db.session.add(svc.MailSyncState(user_id=uid,last_success_at=svc.utc_now(),pending_count=0));db.session.commit()

def fresh(user):
    state=db.session.get(svc.MailSyncState,user.id);state.last_success_at=svc.utc_now();state.pending_count=0;state.last_error=None
    db.session.commit();return {'ready':True}
svc.sync_user_mailbox=fresh

def post(path,data):
    with app.test_client() as client:
        response=client.post(path,headers=headers,json=data)
        return response.status_code,response.get_json()

def original(number):
    with app.app_context():
        school=svc.SalesSchool(school_name=f'Sequence {number}',email=f'seq{number}@example.test',contact_name='Alex',
            status='contacted',school_type='elementary',user_id=uid)
        db.session.add(school);db.session.flush()
        sent=svc.SentEmail(school_name=school.school_name,school_email=school.email,user_id=uid,
            sales_school_id=school.id,sent_at=datetime(2026,11,4,15),responded=False)
        db.session.add(sent);db.session.flush()
        db.session.add(svc.SentMessage(sent_email_id=sent.id,message_id=f'<intro-{number}@example.test>',subject='Intro',kind='outreach',sent_at=sent.sent_at))
        db.session.commit();return sent.id

try:
    steps=[]
    for n in range(1,4):
        code,template=post('/api/outreach/templates',dict(name=f'Follow {n}',kind='followup',step=n,audience='general',subject=f'Follow {n}',body='Hi {contact name} at {school name}'))
        assert code==201,(code,template)
        steps.append(dict(day=[4,10,17][n-1],template_id=template['id'],template_revision=template['revision']))
    code,sequence=post('/api/outreach/sequences',dict(name='Durable test',audience='all',start_hour=9,end_hour=17,steps=steps));assert code==201
    oid=original(1)
    settings=dict(sequence_id=sequence['id'],revision=1,original_ids=[oid],mode='automatic',start_date='2026-11-05',end_date='2026-12-20')
    code,preview=post('/api/outreach/sequence-enrollments/preview',settings);assert code==200,(code,preview)
    commit=dict(review_id=preview['review_id'],settings=settings,confirm='AUTHORIZE_AUTOMATIC_SEQUENCE')
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:post('/api/outreach/sequence-enrollments/commit',commit),range(2)))
    assert sorted(code for code,_ in results)==[200,201] and results[0][1]==results[1][1],results
    with app.app_context():
        step=svc.SequenceStep.query.order_by(svc.SequenceStep.number).first();due=step.due_at;eid=step.enrollment_id
    tick.return_value=due
    def schedule(_):
        with app.app_context():return svc.schedule_sequences()
    with ThreadPoolExecutor(2) as pool:queued=list(pool.map(schedule,range(2)))
    assert sum(queued)==1,queued
    def work(worker):
        with app.app_context():return svc.run_outreach_cycle(worker,max_jobs=1)
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(work,['worker-a','worker-b']))
    assert len(smtp.delivered)==1,smtp.delivered
    with app.app_context():
        assert svc.SequenceStep.query.filter_by(enrollment_id=eid,number=1).one().status=='sent'
        assert svc.ContactOutreachLedger.query.count()==1
        assert svc.SentMessage.query.filter_by(kind='sequence_followup').count()==1
    print('PASS migration twice/RLS/grants; competing enrollment commits, two schedulers and two workers: one durable step and one fake-SMTP delivery',flush=True)

    # Queue the next step before closing time; dispatch after closing must defer.
    with app.app_context():next_due=svc.SequenceStep.query.filter_by(enrollment_id=eid,number=2).one().due_at
    tick.return_value=next_due
    with app.app_context():assert svc.schedule_sequences()==1
    tick.return_value=next_due.replace(hour=23)
    work('worker-a')
    assert len(smtp.delivered)==1
    with app.app_context():
        batch=outreach.OutreachBatch.query.filter_by(kind='sequence',status='queued').one()
        assert batch.available_at>svc.utc_now()
        resume=batch.available_at
    # Simulate a new process on the next business day.
    tick.return_value=resume
    work('worker-restarted')
    assert len(smtp.delivered)==2
    print('PASS outside-window dispatch deferred; restarted worker delivered only at the next business window',flush=True)

    # Provider accepts DATA then loses the response. Never replay automatically.
    with app.app_context():third_due=svc.SequenceStep.query.filter_by(enrollment_id=eid,number=3).one().due_at
    tick.return_value=third_due;smtp.drop_after={smtp.attempts+1}
    work('worker-a');work('worker-restarted')
    assert len(smtp.delivered)==3
    with app.app_context():
        assert svc.SequenceStep.query.filter_by(enrollment_id=eid,number=3).one().status=='unconfirmed'
        assert db.session.get(svc.SequenceEnrollment,eid).status=='paused'
    print('PASS ambiguous socket outcome retained and paused; restart did not resend it',flush=True)

    # All manual batches now use the same five-at-a-time durable queue.
    tick.return_value=datetime(2026,12,1,15)
    with app.app_context():
        schools=[svc.SalesSchool(school_name=f'Chunk {i}',email=f'chunk{i}@example.test',contact_name='Sam',status='pending',school_type='elementary',user_id=uid) for i in range(12)]
        db.session.add_all(schools);db.session.commit();ids=[s.id for s in schools]
    payload=dict(school_ids=ids,kind='custom',subject='A controlled test',body='Hi [contact_name]',attachment_ids=[],contact_mode=True,audience='all',campaign_id='standard',contact_contexts={})
    code,review=post('/api/email-preview',payload);assert code==200
    code,queued=post('/api/outreach/batches',{**payload,'preview_token':review['preview_token']});assert code==202,(code,queued)
    before=len(smtp.delivered)
    work('worker-a');assert len(smtp.delivered)==before+5
    def complaint(user):
        svc.record_mail_signal('chunk0@example.test','complaint','test:chunk-complaint','Synthetic complaint',actor_id=uid)
        db.session.commit();return fresh(user)
    svc.sync_user_mailbox=complaint
    work('worker-b');assert len(smtp.delivered)==before+5
    with app.app_context():assert db.session.get(outreach.OutreachBatch,queued['batch_id']).status=='paused'
    print('PASS durable manual chunks: five messages then detected complaint; no sixth message',flush=True)
    print('Sequence PostgreSQL/real-socket fake-SMTP checks passed. No Gmail, production database or hosted worker used.',flush=True)
finally:
    clock.stop();smtp.server.shutdown();smtp.server.server_close()
    with app.app_context():db.session.remove();engine.dispose()
