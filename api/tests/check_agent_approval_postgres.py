"""Destructive disposable PostgreSQL + real-socket fake-SMTP approval check."""
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import text
from sqlalchemy.engine import make_url

url=os.environ.get('AGENT_APPROVAL_TEST_DATABASE_URL','')
parsed=make_url(url)
if parsed.host not in ('127.0.0.1','localhost') or parsed.database!='psa_agent_approval_test':
    raise SystemExit('Refusing: use disposable loopback database psa_agent_approval_test')
os.environ['LOADTEST_DATABASE_URL']=url
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from api.tests import load_outreach as harness
from api import api as svc,outreach
app,db,smtp=svc.app,svc.db,harness.smtp
app.config['TESTING']=True
os.environ['OUTREACH_SEND_DELAY']='0'
new={'agent_outreach_drafts','agent_outreach_events'}
with app.app_context():
    engine=db.engine
    with engine.begin() as connection:connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
    db.metadata.create_all(engine,tables=[table for name,table in db.metadata.tables.items() if name not in new])
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE agent_api_keys ALTER COLUMN scopes TYPE VARCHAR(40)'))
        for role in ('anon','authenticated'):
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
    migration=(Path(__file__).resolve().parents[1]/'migrations/20261105_agent_batch_approval.sql').read_text()
    for _ in range(2):
        raw=engine.raw_connection()
        try:
            with raw.cursor() as cursor:cursor.execute(migration)
            raw.commit()
        finally:raw.close()
    assert db.session.execute(text("SELECT character_maximum_length FROM information_schema.columns WHERE table_name='agent_api_keys' AND column_name='scopes'")).scalar()==255
    for table in new:
        assert db.session.execute(text('SELECT relrowsecurity FROM pg_class WHERE relname=:t'),dict(t=table)).scalar()
        for role in ('anon','authenticated'):
            for permission in ('SELECT','INSERT','UPDATE','DELETE'):
                assert not db.session.execute(text('SELECT has_table_privilege(:r,:t,:p)'),dict(r=role,t=table,p=permission)).scalar()
    user=svc.User(name='Agent Rep',email='agent@example.test',admin=False,password_hash='x',email_password=svc.encrypt_password('fake-only'))
    db.session.add(user);db.session.commit();uid=user.id
    human={'Authorization':'Bearer '+svc.create_access_token(identity=str(uid))}
    db.session.add(svc.MailSyncState(user_id=uid,last_success_at=svc.utc_now(),pending_count=0));db.session.commit()
def fresh(user):
    state=db.session.get(svc.MailSyncState,user.id);state.last_success_at=svc.utc_now();state.pending_count=0;state.last_error=None
    db.session.commit();return {'ready':True}
svc.sync_user_mailbox=fresh
def post(path,data,headers=human):
    with app.test_client() as client:
        result=client.post(path,json=data,headers=headers);return result.status_code,result.get_json()
def school(name):
    with app.app_context():
        row=svc.SalesSchool(school_name=name,email=name.lower().replace(' ','')+'@example.test',contact_name='Sam',school_type='elementary',status='pending',user_id=uid)
        db.session.add(row);db.session.commit();return row.id
def prepared(ids,headers):
    code,draft=post('/api/agent/v1/outreach/drafts',dict(kind='custom',school_ids=ids,subject='Hello [school_name]',body='Hi [contact_name]',audience='all',attachment_ids=[]),headers)
    assert code==201,(code,draft)
    code,result=post('/api/agent-outreach-drafts/'+draft['id']+'/approve',dict(revision=draft['revision']))
    assert code==200,(code,result)
    return draft
def work(name):
    with app.app_context():return svc.run_outreach_cycle(name,max_jobs=1)
try:
    code,key=post('/api/agent-keys',dict(name='Local only',scope='read',expires_in_days=7,capabilities=['outreach:prepare','outreach:send','outreach:read','schools:import'],confirm_send=True))
    assert code==201,(code,key)
    agent={'Authorization':'Bearer '+key['key']}
    draft=prepared([school('Race One'),school('Race Two'),school('Race Three')],agent)
    execute='/api/agent/v1/outreach/drafts/'+draft['id']+'/execute'
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:post(execute,{},agent),range(2)))
    assert sorted(r[0] for r in results)==[200,202],results
    assert len({r[1]['batch_id'] for r in results})==1,results
    with ThreadPoolExecutor(2) as pool:list(pool.map(work,['worker-a','worker-b']))
    assert len(smtp.delivered)==3,smtp.delivered
    with app.app_context():
        stored=db.session.get(svc.AgentOutreachDraft,draft['id'])
        assert stored.batch_id and stored.approval_id and stored.approved_by==uid and stored.key_id==key['id']
        assert svc.AgentOutreachEvent.query.filter_by(draft_id=draft['id'],event='queued').count()==1
        assert svc.OutreachAttempt.query.count()==3
    print('PASS migration twice/RLS/grants; concurrent execute and two workers: one approved batch, three fake-SMTP deliveries and audit linkage',flush=True)

    draft=prepared([school('Revocation Race')],agent)
    def execute_or_revoke(which):
        if which=='execute':return post('/api/agent/v1/outreach/drafts/'+draft['id']+'/execute',{},agent)
        return post('/api/agent-outreach-drafts/'+draft['id']+'/revoke',dict(revision=1))
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(execute_or_revoke,['execute','revoke']))
    assert results[0][0] in (202,409) and results[1][0]==200,results
    work('worker-restarted');assert len(smtp.delivered)==3
    print('PASS concurrent execution/revocation serializes; no revoked message sent by restarted worker',flush=True)

    draft=prepared([school('Key Revoke')],agent)
    assert post('/api/agent/v1/outreach/drafts/'+draft['id']+'/execute',{},agent)[0]==202
    with app.test_client() as client:assert client.delete('/api/agent-keys/'+str(key['id']),headers=human).status_code==200
    work('worker-restarted');assert len(smtp.delivered)==3
    assert post('/api/agent/v1/outreach/drafts/'+draft['id']+'/execute',{},agent)[0]==401
    print('PASS revoked preparing key blocks queued dispatch and future execution; no production database or Gmail used',flush=True)
finally:
    smtp.server.shutdown();smtp.server.server_close()
    with app.app_context():db.session.remove();engine.dispose()
