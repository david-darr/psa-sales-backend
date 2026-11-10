"""Disposable loopback Postgres + socket SMTP. Never accepts a hosted URL."""
import os
import sys
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import text
from sqlalchemy.engine import make_url

url=os.environ.get('CAMPAIGN_TEST_DATABASE_URL','')
parsed=make_url(url)
if parsed.host not in ('localhost','127.0.0.1') or parsed.database!='psa_campaign_test':
    raise SystemExit('Use only the disposable loopback database psa_campaign_test')
os.environ['LOADTEST_DATABASE_URL']=url
os.environ['CAMPAIGN_AUTOMATION_ENABLED']='true'
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from api.tests import load_outreach as harness
from api import api as svc, outreach

app,db,smtp=svc.app,svc.db,harness.smtp
tables={'approved_campaign_plans','approved_campaign_members','approved_campaign_events','approved_campaign_summaries'}
clock=patch.object(svc,'utc_now',return_value=datetime(2026,11,9,15));clock.start()

def post(path,data,headers):
    with app.test_client() as client:
        result=client.post(path,json=data,headers=headers);return result.status_code,result.get_json()

try:
    with app.app_context():
        engine=db.engine
        with engine.begin() as c:c.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
        db.metadata.create_all(engine,tables=[t for name,t in db.metadata.tables.items() if name not in tables])
        with engine.begin() as c:
            for role in ('anon','authenticated'):
                c.execute(text(f"DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
        migration=(Path(__file__).resolve().parents[1]/'migrations/20261108_approved_campaigns.sql').read_text()
        for _ in range(2):
            raw=engine.raw_connection()
            try:
                with raw.cursor() as cursor:cursor.execute(migration)
                raw.commit()
            finally:raw.close()
        for name in tables:
            assert db.session.execute(text('SELECT relrowsecurity FROM pg_class WHERE relname=:n'),dict(n=name)).scalar()
            for role in ('anon','authenticated'):
                for permission in ('SELECT','INSERT','UPDATE','DELETE'):
                    assert not db.session.execute(text('SELECT has_table_privilege(:r,:n,:p)'),dict(r=role,n=name,p=permission)).scalar()
        user=svc.User(name='Campaign fixture',email='campaign@example.test',admin=True,password_hash='x',email_password=svc.encrypt_password('fake-only'))
        db.session.add(user);db.session.commit();uid=user.id
        human={'Authorization':'Bearer '+svc.create_access_token(identity=str(uid))}
        db.session.add(svc.MailSyncState(user_id=uid,last_success_at=svc.utc_now(),pending_count=0))
        schools=[]
        for number in range(12):
            school=svc.SalesSchool(school_name=f'Campaign test {number}',email=f'campaign-{number}@example.test',contact_name='Pat',school_type='elementary',status='pending',user_id=uid)
            db.session.add(school);db.session.flush();schools.append(school.id)
        db.session.commit()
    code,key=post('/api/agent-keys',dict(name='Fake campaign fixture',scope='read',expires_in_days=7,capabilities=['outreach:read','outreach:prepare','outreach:send'],confirm_send=True),human)
    assert code==201,(code,key)
    agent={'Authorization':'Bearer '+key['key']}
    code,template=post('/api/outreach/templates',dict(name='Campaign fixture',kind='initial',step=0,audience='general',subject='Hello {school name}',body='Hi {contact name}'),human)
    assert code==201,(code,template)
    def prepare(ids):
        code,result=post('/api/agent/v1/outreach/campaign-plans',dict(name='Fixed campaign',school_ids=ids,audience='all',template_id=template['id'],template_revision=1,daily_cap=20,start_date='2026-11-09',end_date='2026-12-20'),agent)
        assert code==201,(code,result);return result
    def approve(plan):
        return post('/api/outreach/campaign-plans/'+plan['id']+'/approve',dict(revision=plan['revision'],confirm='AUTHORIZE_CAMPAIGN'),human)
    plan=prepare(schools[:10])
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:approve(plan),range(2)))
    assert sorted(r[0] for r in results)==[200,409],results
    def schedule(_):
        with app.app_context():return svc.schedule_campaigns(5)
    with ThreadPoolExecutor(2) as pool:counts=list(pool.map(schedule,range(2)))
    assert sum(counts)==10,counts
    with app.app_context():
        assert svc.CampaignMember.query.filter_by(plan_id=plan['id']).count()==10
        assert outreach.OutreachRecipient.query.count()==10
        assert svc.ContactOutreachLedger.query.count()==10
        assert svc.CampaignPlanEvent.query.filter_by(event='approve').count()==1

    def fresh(user):
        state=db.session.get(svc.MailSyncState,user.id);state.last_success_at=svc.utc_now();state.pending_count=0;state.last_error=None
        db.session.commit();return {'ready':True}
    svc.sync_user_mailbox=fresh
    def work(name):
        with app.app_context():return svc.run_outreach_cycle(name,max_jobs=2)
    with ThreadPoolExecutor(2) as pool:list(pool.map(work,['campaign-worker-a','campaign-worker-b']))
    assert len(smtp.delivered)==10,smtp.delivered
    assert len({r['rcpt'] for r in smtp.delivered})==10
    plan2=prepare(schools[10:]);code,approved=approve(plan2);assert code==200
    # Cancellation survives a new worker instance, with no unapproved retry.
    def cancel_or_schedule(which):
        if which=='cancel':return post('/api/outreach/campaign-plans/'+plan2['id']+'/cancel',dict(revision=approved['revision']),human)
        return schedule(0)
    with ThreadPoolExecutor(2) as pool:race=list(pool.map(cancel_or_schedule,['cancel','schedule']))
    assert race[0][0]==200,race
    work('campaign-worker-after-restart');assert len(smtp.delivered)==10
    print('PASS: idempotent migration/RLS/grants; concurrent human approvals, scheduling and workers; ten unique socket-SMTP messages; cancellation across restart. No Gmail or hosted database.')
finally:
    clock.stop();smtp.server.shutdown();smtp.server.server_close()
    with app.app_context():db.session.remove();db.engine.dispose()
