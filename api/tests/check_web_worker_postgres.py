"""Real web-host threads, disposable PostgreSQL and loopback SMTP only."""
import os
import sys
import time
from pathlib import Path
from sqlalchemy.engine import make_url
from sqlalchemy import text

url=os.environ.get('WEB_WORKER_TEST_DATABASE_URL','')
parsed=make_url(url)
if parsed.host not in ('localhost','127.0.0.1') or parsed.database!='psa_web_worker_test':
    raise SystemExit('Use only the disposable loopback database psa_web_worker_test')
os.environ['LOADTEST_DATABASE_URL']=url
os.environ['OUTREACH_WORKER_MODE']='external'
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from api.tests import load_outreach as harness
from api import api as svc,outreach
from api.web_outreach_worker import WebOutreachWorker

app,db,smtp=svc.app,svc.db,harness.smtp
controllers=[]

def wait_until(predicate,limit=15):
    end=time.monotonic()+limit
    while time.monotonic()<end:
        if predicate():return
        time.sleep(.05)
    raise AssertionError('Timed out waiting for local worker result')

def call(path,data):
    with app.test_client() as client:
        response=client.post(path,headers=headers,json=data)
        assert response.status_code in (200,201,202),(path,response.status_code,response.get_json())
        return response.get_json()

def queue(prefix,count):
    with app.app_context():
        schools=[svc.SalesSchool(school_name=prefix+str(i),email=prefix+str(i)+'@example.test',contact_name='Pat',school_type='elementary',status='pending',user_id=uid) for i in range(count)]
        db.session.add_all(schools);db.session.commit();ids=[s.id for s in schools]
    data=dict(kind='custom',school_ids=ids,subject='Hello [school_name]',body='Hello [contact_name]',contact_mode=True,audience='all',attachment_ids=[])
    preview=call('/api/email-preview',data)
    return call('/api/outreach/batches',dict(**data,preview_token=preview['preview_token']))['batch_id']

def start():
    worker=WebOutreachWorker(app,db,svc,poll_seconds=1);controllers.append(worker);worker.start();return worker

def stop_all():
    for worker in controllers:worker.stop()
    for worker in controllers:worker.stop(5)
    assert all(not w.thread.is_alive() for w in controllers)
    controllers.clear()

try:
    with app.app_context():
        with db.engine.begin() as connection:connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
        db.create_all()
        user=svc.User(name='Local web worker',email='worker@example.test',admin=True,password_hash='x',email_password=svc.encrypt_password('fake-only'))
        db.session.add(user);db.session.commit();uid=user.id
        headers={'Authorization':'Bearer '+svc.create_access_token(identity=str(uid))}
        db.session.add(svc.MailSyncState(user_id=uid,last_success_at=svc.utc_now(),pending_count=0));db.session.commit()
    def fresh(user):
        state=db.session.get(svc.MailSyncState,user.id);state.last_success_at=svc.utc_now();state.pending_count=0;state.last_error=None;db.session.commit();return {'ready':True}
    svc.sync_user_mailbox=fresh
    app.config['OUTREACH_WORKER_MODE']='web'
    smtp.latency=.05
    queue('web-first-',12)
    start();start()
    latencies=[]
    for _ in range(15):
        began=time.monotonic()
        with app.test_client() as client:
            response=client.get('/api/outreach/limits',headers=headers)
            assert response.status_code==200
        latencies.append(time.monotonic()-began);time.sleep(.03)
    wait_until(lambda:len(smtp.delivered)==12)
    stop_all()
    assert len({r['rcpt'] for r in smtp.delivered})==12
    queue('web-restarted-',2);start()
    wait_until(lambda:len(smtp.delivered)==14);stop_all()
    # Provider accepted the next message but lost its SMTP response. Never resend.
    smtp.drop_after={smtp.attempts+1}
    uncertain=queue('web-uncertain-',2);start()
    def finished():
        with app.app_context():return db.session.get(outreach.OutreachBatch,uncertain).status=='done'
    wait_until(finished);stop_all()
    count=len(smtp.delivered);start();time.sleep(1.2);stop_all()
    assert len(smtp.delivered)==count==16
    with app.app_context():
        assert outreach.OutreachRecipient.query.filter_by(batch_id=uncertain,status='unconfirmed').count()==1
        assert svc.SentEmail.query.count()==15
    p95=sorted(latencies)[int(.95*(len(latencies)-1))]
    assert p95<1.5,p95
    print('PASS: two real web-host worker threads, 15 recorded deliveries without duplicates, responsive API (local p95 %.3fs), restart recovery, ambiguous SMTP retained without automatic resend. No Gmail or hosted database.'%p95)
finally:
    stop_all();smtp.server.shutdown();smtp.server.server_close()
    with app.app_context():db.session.remove();db.engine.dispose()
