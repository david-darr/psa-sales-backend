"""Destructive LOCAL integration/load check; never collected by pytest.

CONTACT_OUTREACH_TEST_DATABASE_URL must name psa_contact_outreach_test on
loopback. Uses the existing real-socket fake SMTP; Gmail/IMAP are never called.
"""
import os
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import text
from sqlalchemy.engine import make_url

url = os.environ.get('CONTACT_OUTREACH_TEST_DATABASE_URL', '')
parsed = make_url(url)
if parsed.host not in ('127.0.0.1', 'localhost') or parsed.database != 'psa_contact_outreach_test':
    raise SystemExit('Refusing: use a disposable loopback DB named psa_contact_outreach_test')
os.environ['LOADTEST_DATABASE_URL'] = url
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api.tests import load_outreach as harness
from api import api as svc, outreach
app, db, smtp = svc.app, svc.db, harness.smtp
app.config['TESTING'] = True
os.environ['OUTREACH_DAILY_LIMIT'] = '150'
os.environ['OUTREACH_SEND_DELAY'] = '0'
svc.sync_user_mailbox = lambda *args, **kwargs: {'ready': True}

with app.app_context():
    engine = db.engine
    with engine.begin() as connection:
        connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
    new = {'outreach_campaigns', 'outreach_contact_reviews', 'outreach_contact_ledger', 'mail_contact_signals', 'outreach_send_attempts'}
    db.metadata.create_all(engine, tables=[table for name, table in db.metadata.tables.items() if name not in new])
    with engine.begin() as connection:
        for field in ('campaign_id', 'paused_reason'):
            connection.execute(text(f'ALTER TABLE outreach_batches DROP COLUMN {field}'))
        for field in ('contact_id', 'contact_link_id', 'contact_version', 'link_version', 'attempted_at'):
            connection.execute(text(f'ALTER TABLE outreach_recipients DROP COLUMN {field}'))
        for role in ('anon', 'authenticated'):
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
    migration = (Path(__file__).resolve().parents[1] / 'migrations/20261105_contact_outreach.sql').read_text()
    for _ in range(2):
        raw = engine.raw_connection()
        try:
            with raw.cursor() as cursor: cursor.execute(migration)
            raw.commit()
        finally: raw.close()
    for table in new:
        assert db.session.execute(text('SELECT relrowsecurity FROM pg_class WHERE relname=:t'), {'t': table}).scalar()
        for role in ('anon', 'authenticated'):
            for privilege in ('SELECT', 'INSERT', 'UPDATE', 'DELETE'):
                assert not db.session.execute(text('SELECT has_table_privilege(:r,:t,:p)'), dict(r=role, t=table, p=privilege)).scalar()
    db.session.remove()

tokens = {}
def rep(number, count, shared=False):
    with app.app_context():
        user = svc.User(name=f'Rep {number}', email=f'rep{number}@example.test', password_hash='x', admin=False,
                        email_password=svc.encrypt_password('fake-local-only'))
        db.session.add(user); db.session.flush()
        schools = [svc.SalesSchool(school_name=f'School {number}-{i}', user_id=user.id, school_type='elementary',
            status='pending', contact_name='Sam', email='shared@example.test' if shared else f's{number}-{i}@example.test') for i in range(count)]
        db.session.add_all(schools); db.session.commit()
        tokens[user.id] = svc.create_access_token(identity=str(user.id))
        return user.id, [s.id for s in schools]

def post(uid, path, data):
    with app.test_client() as client:
        response = client.post(path, headers={'Authorization': 'Bearer ' + tokens[uid]}, json=data)
        return response.status_code, response.get_json()

def payload(ids):
    return dict(kind='custom', school_ids=ids, contact_mode=True, audience='all', campaign_id='standard',
        contact_contexts={}, subject='Hello [school_name]', body='Hi [contact_name], from [user_name]', attachment_ids=[])

def prepare(uid, ids):
    body = payload(ids)
    code, data = post(uid, '/api/email-preview', body)
    assert code == 200, (code, data)
    return {**body, 'preview_token': data['preview_token']}

# Cross-rep race: both previews are valid before either request reserves.
left, right = rep(1, 1, shared=True), rep(2, 1, shared=True)
reviews = [prepare(uid, ids) for uid, ids in (left, right)]
with patch.object(outreach, 'start_worker'):
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda pair: post(pair[0], '/api/outreach/batches', pair[1]),
            [(left[0], reviews[0]), (right[0], reviews[1])]))
assert sorted(code for code, data in results) == [202, 409], results
# Replayed review is idempotent under simultaneous submissions.
winner = 0 if results[0][0] == 202 else 1
winning_uid = (left, right)[winner][0]
with patch.object(outreach, 'start_worker'):
    with ThreadPoolExecutor(4) as pool:
        repeated = list(pool.map(lambda _: post(winning_uid, '/api/outreach/batches', reviews[winner]), range(4)))
assert all(code == 200 and data['batch_id'] == results[winner][1]['batch_id'] for code, data in repeated), repeated
with app.app_context():
    batch = db.session.get(outreach.OutreachBatch, results[winner][1]['batch_id'])
    race_id, race_token = batch.id, batch.worker_token
outreach.run_batch(app, race_id, race_token, delay=0)
assert len(smtp.delivered) == 1, smtp.delivered
print('PASS migration twice, RLS/grants, cross-rep contact reservation race, four-way review replay, exactly one fake-SMTP delivery', flush=True)

# A complaint and an explicitly reviewed retry must share the same lock order.
uid, ids = rep(3, 1)
body = prepare(uid, ids)
with patch.object(outreach, 'start_worker'):
    code, queued = post(uid, '/api/outreach/batches', body)
assert code == 202
bid = queued['batch_id']
with app.app_context():
    batch = db.session.get(outreach.OutreachBatch, bid); batch.status = 'done'
    recipient = outreach.OutreachRecipient.query.filter_by(batch_id=bid).one(); recipient.status = 'failed'
    cid = recipient.contact_id
    db.session.commit()
code, review = post(uid, f'/api/outreach/batches/{bid}/retry-preview', {})
assert code == 200
with patch.object(outreach, 'start_worker'):
    with ThreadPoolExecutor(2) as pool:
        future = pool.submit(post, uid, f'/api/outreach/batches/{bid}/retry', {'preview_token': review['preview_token']})
        report = pool.submit(post, uid, f'/api/contacts/{cid}/report', {'kind': 'complaint', 'detail': 'Synthetic concurrent phone complaint'})
        result, signal = future.result(timeout=20), report.result(timeout=20)
assert result[0] in (202, 409) and signal[0] == 200, (result, signal)
with app.app_context():
    assert db.session.get(svc.Contact, cid).do_not_contact
    batch = db.session.get(outreach.OutreachBatch, bid)
    token = batch.worker_token
outreach.run_batch(app, bid, token, delay=0)
assert len(smtp.delivered) == 1, 'Complaint race sent a suppressed mailbox'
print('PASS concurrent reviewed retry / complaint: no deadlock and no SMTP delivery to the suppressed mailbox', flush=True)

def run_scale(label, reps, per_rep):
    people = [rep(100 + len(tokens), per_rep) for _ in range(reps)]
    prepared = [(uid, prepare(uid, ids)) for uid, ids in people]
    before = len(smtp.delivered)
    with app.app_context(): ledger_before = svc.ContactOutreachLedger.query.count()
    started = time.monotonic()
    with patch.object(outreach, 'start_worker'):
        with ThreadPoolExecutor(min(reps, 12)) as pool:
            queued = list(pool.map(lambda pair: post(pair[0], '/api/outreach/batches', pair[1]), prepared))
    assert all(code == 202 for code, _ in queued), queued
    jobs = []
    with app.app_context():
        for _, result in queued:
            batch = db.session.get(outreach.OutreachBatch, result['batch_id'])
            jobs.append((batch.id, batch.worker_token))
    latencies = []
    with ThreadPoolExecutor(min(reps, 12)) as pool:
        futures = [pool.submit(outreach.run_batch, app, bid, token, 0) for bid, token in jobs]
        while not all(f.done() for f in futures):
            then = time.monotonic()
            with app.test_client() as client:
                response = client.get('/api/outreach/limits', headers={'Authorization': 'Bearer ' + tokens[people[0][0]]})
                assert response.status_code == 200, response.get_json()
            latencies.append(time.monotonic() - then)
            time.sleep(.02)
        for future in futures: future.result()
    delivered = smtp.delivered[before:]
    assert len(delivered) == reps * per_rep, (label, len(delivered))
    assert len({message['rcpt'] for message in delivered}) == len(delivered), 'Duplicate mailbox delivery'
    with app.app_context():
        assert outreach.OutreachRecipient.query.filter(outreach.OutreachRecipient.batch_id.in_([j[0] for j in jobs]),
            outreach.OutreachRecipient.status != 'sent').count() == 0
        assert svc.ContactOutreachLedger.query.count() == ledger_before + reps * per_rep
        sid = people[0][1][0]
        recipient_id = outreach.OutreachRecipient.query.filter_by(school_id=sid).one().id
        db.session.execute(text('DELETE FROM sales_schools WHERE id=:id'), {'id': sid})
        db.session.commit(); db.session.expire_all()
        recipient = db.session.get(outreach.OutreachRecipient, recipient_id)
        assert recipient.school_id is None and recipient.contact_link_id is None
        assert svc.ContactOutreachLedger.query.filter_by(recipient_id=recipient_id).count() == 1
    p95 = sorted(latencies)[max(0, int(len(latencies)*.95)-1)] if latencies else 0
    assert p95 < 2, (label, 'Web requests stalled', p95)
    print(f'PASS {label}: {reps} reps x {per_rep} contacts; {len(delivered)} socket deliveries, no duplicates; {time.monotonic()-started:.2f}s; local web p95={p95*1000:.0f}ms', flush=True)

try:
    smtp.latency = .005
    run_scale('small', 1, 5)
    run_scale('heavy', 12, 100)
    print('Contact outreach Postgres/load checks passed. No real mail, external inbox or production database used.', flush=True)
finally:
    smtp.server.shutdown(); smtp.server.server_close()
    with app.app_context(): db.session.remove(); engine.dispose()
