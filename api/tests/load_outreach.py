"""Load and fault tests for the outreach batch system (not collected by pytest).

Runs the real Flask app and real worker threads. Mail goes over a real socket to a local fake
SMTP server, and data lives in a throwaway local Postgres. It refuses to run unless the database
is on localhost and never contacts smtp.gmail.com.

    docker run -d --name psa-loadtest-pg -e POSTGRES_PASSWORD=loadtest -p 55432:5432 postgres:16
    set LOADTEST_DATABASE_URL=postgresql://postgres:loadtest@127.0.0.1:55432/postgres
    python api/tests/load_outreach.py [scenario ...]      (no names = all)
"""
import base64
import itertools
import json
import logging
import os
import re
import smtplib
import socketserver
import sys
import threading
import time
from collections import Counter
from datetime import timedelta
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

DB_URL = os.environ.get('LOADTEST_DATABASE_URL', '')
if urlparse(DB_URL).hostname not in ('127.0.0.1', 'localhost'):
    sys.exit('Refusing to run: set LOADTEST_DATABASE_URL to a postgres on localhost.')
os.environ['DATABASE_URL'] = DB_URL
os.environ['JWT_SECRET_KEY'] = 'loadtest-key'
os.environ['MAIL_CREDENTIAL_KEY'] = base64.urlsafe_b64encode(b'1' * 32).decode()
os.environ['PSA_DISABLE_SCHEDULER'] = 'true'
os.environ['OUTREACH_SEND_DELAY'] = '0'
os.environ['OUTREACH_DAILY_LIMIT'] = '100000'

from sqlalchemy import event, text  # noqa: E402
from api import api as service  # noqa: E402
from api import outreach  # noqa: E402

app, db = service.app, service.db
app.config['TESTING'] = False
TERMINAL = ('done', 'cancelled', 'stalled')


# --------------------------------------------------------------------------- fake SMTP

class FakeSmtp:
    def __init__(self):
        self.lock = threading.Lock()
        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _Handler)
        self.server.daemon_threads = True
        self.server.allow_reuse_address = True
        self.server.state = self
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.reset()

    def reset(self):
        with self.lock:
            self.delivered, self.attempts, self.connections = [], 0, 0
            self.current, self.peak = 0, 0
            self.latency, self.latency_at = 0.0, {}
            self.reject = set()
            self.quota_after = None
            self.drop_before, self.drop_after = set(), set()

    def decide(self, sender, rcpt, raw):
        with self.lock:
            self.attempts += 1
            n = self.attempts
            wait = self.latency_at.get(n, self.latency)
        if wait:
            time.sleep(wait)
        with self.lock:
            if n in self.drop_before:
                return 'drop'
            if self.quota_after is not None and len(self.delivered) >= self.quota_after:
                return 'quota'
            match = re.search(rb'(?im)^Message-ID:\s*(<[^>]+>)', raw)
            self.delivered.append({'sender': sender, 'rcpt': rcpt, 'mid': match.group(1).decode() if match else None,
                                   'bytes': len(raw), 'at': time.time()})
            return 'drop' if n in self.drop_after else 'ok'


class _Handler(socketserver.StreamRequestHandler):
    def reply(self, line):
        self.wfile.write(line.encode() + b'\r\n')
        self.wfile.flush()

    def handle(self):
        st = self.server.state
        with st.lock:
            st.connections += 1
            st.current += 1
            st.peak = max(st.peak, st.current)
        try:
            self.reply('220 fake ESMTP')
            sender, rcpts = '', []
            while True:
                raw = self.rfile.readline()
                if not raw:
                    return
                line = raw.decode('latin-1').strip()
                verb = line.split(' ', 1)[0].upper()
                if verb in ('EHLO', 'HELO'):
                    self.reply('250 fake')
                elif verb == 'MAIL':
                    sender, rcpts = line[line.index('<') + 1:line.index('>')], []
                    self.reply('250 OK')
                elif verb == 'RCPT':
                    addr = line[line.index('<') + 1:line.index('>')]
                    if addr in st.reject:
                        self.reply('550 5.1.1 no such user')
                    else:
                        rcpts.append(addr)
                        self.reply('250 OK')
                elif verb == 'DATA':
                    self.reply('354 go ahead')
                    chunks = []
                    while True:
                        part = self.rfile.readline()
                        if not part:
                            return
                        if part in (b'.\r\n', b'.\n'):
                            break
                        chunks.append(part[1:] if part.startswith(b'..') else part)
                    verdict = st.decide(sender, rcpts[0] if rcpts else '', b''.join(chunks))
                    if verdict == 'drop':
                        return
                    if verdict == 'quota':
                        self.reply('550 5.4.5 Daily user sending quota exceeded')
                    else:
                        self.reply('250 OK queued')
                elif verb == 'RSET' or verb == 'NOOP':
                    self.reply('250 OK')
                elif verb == 'QUIT':
                    self.reply('221 bye')
                    return
                else:
                    self.reply('502 not implemented')
        except (ConnectionError, OSError):
            return
        finally:
            with st.lock:
                st.current -= 1


smtp = FakeSmtp()
SMTP_TIMEOUT = [15]
service.open_smtp_connection = lambda from_email, password: smtplib.SMTP('127.0.0.1', smtp.port, timeout=SMTP_TIMEOUT[0])


# --------------------------------------------------------------------------- instrumentation

class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.queries = 0
        self.peak_conns = 0
        self.peak_idle_tx = 0
        self._stop = threading.Event()

    def count(self):
        with self.lock:
            self.queries += 1

    def start_monitor(self):
        import psycopg2
        self._stop.clear()
        self.peak_conns = self.peak_idle_tx = 0

        def run():
            conn = psycopg2.connect(DB_URL)
            conn.autocommit = True
            cur = conn.cursor()
            while not self._stop.is_set():
                cur.execute("select count(*), count(*) filter (where state = 'idle in transaction') "
                            "from pg_stat_activity where datname = current_database() and pid <> pg_backend_pid()")
                total, idle = cur.fetchone()
                self.peak_conns, self.peak_idle_tx = max(self.peak_conns, total), max(self.peak_idle_tx, idle)
                time.sleep(0.1)
            conn.close()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop_monitor(self):
        self._stop.set()
        self.thread.join(2)


M = Metrics()
with app.app_context():
    event.listen(db.engine, 'before_cursor_execute', lambda *a, **k: M.count())


class LogCatcher(logging.Handler):
    def __init__(self):
        super().__init__(logging.ERROR)
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


catcher = LogCatcher()
logging.getLogger('api.outreach').addHandler(catcher)
logging.getLogger('api.outreach').propagate = False
logging.getLogger('api.api').addHandler(catcher)

# --------------------------------------------------------------------------- helpers

CHECKS = []


def check(scenario, name, ok, detail=''):
    CHECKS.append((scenario, name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f'  [{detail}]' if detail else ''), flush=True)


def reset_world():
    smtp.reset()
    catcher.records.clear()
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()


def make_rep(n):
    with app.app_context():
        user = service.User(name=f'Rep {n}', email=f'rep{n}@psa.test', admin=False, password_hash='x',
                            email_password=service.encrypt_password('dummy-app-password'))
        db.session.add(user)
        db.session.commit()
        return user.id


def make_schools(uid, count, offset=0):
    with app.app_context():
        rows = [service.SalesSchool(school_name=f'School {uid}-{i}', email=f's{i}-u{uid}@school.test', school_type='preschool',
                                    user_id=uid, status='pending', contact_name='Pat') for i in range(offset, offset + count)]
        db.session.add_all(rows)
        db.session.commit()
        return [row.id for row in rows]


def world(reps, per_rep):
    reset_world()
    out = []
    for n in range(1, reps + 1):
        uid = make_rep(n)
        out.append((uid, make_schools(uid, per_rep)))
    return out


def headers(uid):
    with app.app_context():
        return {'Authorization': 'Bearer ' + service.create_access_token(identity=str(uid))}


def post_batch(uid, ids, kind='custom', **extra):
    body = {'school_ids': ids, 'kind': kind, 'subject': 'Hello [school_name]', 'body': 'Hi [contact_name], from [user_name]'}
    if kind != 'custom':
        body = {'school_ids': ids, 'kind': kind}
    body.update(extra)
    client = app.test_client()
    response = client.post('/api/outreach/batches', headers=headers(uid), json=body)
    return client, response


def wait_batch(client, uid, batch_id, timeout=600):
    hdr, started = headers(uid), time.time()
    while time.time() - started < timeout:
        data = client.get('/api/outreach/batches?limit=50', headers=hdr).get_json()
        mine = next((item for item in data['items'] if item['id'] == batch_id), None)
        if mine and mine['status'] in TERMINAL:
            return client.get(f'/api/outreach/batches/{batch_id}', headers=hdr).get_json()
        time.sleep(0.25)
    return None


def run_one(uid, ids, kind='custom', **extra):
    started = time.time()
    client, response = post_batch(uid, ids, kind, **extra)
    result = {'uid': uid, 'status_code': response.status_code, 'secs': 0.0, 'final': None, 'json': response.get_json()}
    if response.status_code == 202:
        result['final'] = wait_batch(client, uid, response.get_json()['batch_id'])
    result['secs'] = time.time() - started
    return result


def run_many(specs, **extra):
    results = [None] * len(specs)

    def work(i, uid, ids):
        results[i] = run_one(uid, ids, **extra)
    threads = [threading.Thread(target=work, args=(i, uid, ids)) for i, (uid, ids) in enumerate(specs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def audit():
    """Cross-check what the SMTP server received against what the database believes."""
    per = Counter((d['sender'], d['rcpt']) for d in smtp.delivered)
    dupes = {f'{k[1]}': v for k, v in per.items() if v > 1}
    wrong = [d for d in smtp.delivered if d['sender'] != 'rep' + re.search(r'-u(\d+)@', d['rcpt']).group(1) + '@psa.test'
             and d['sender'] != f"rep{re.search(r'-u(\d+)@', d['rcpt']).group(1)}@psa.test"]
    with app.app_context():
        recipients = db.session.query(outreach.OutreachRecipient).all()
        status = Counter(r.status for r in recipients)
        sent_to = {r.email for r in recipients if r.status == 'sent'}
        failed_to = {r.email for r in recipients if r.status == 'failed'}
        sent_rows = db.session.query(service.SentEmail).count()
        stage = Counter(row.status for row in db.session.query(service.SalesSchool).all())
    delivered_to = {d['rcpt'] for d in smtp.delivered}
    return {'delivered': len(smtp.delivered), 'unique_delivered': len(delivered_to), 'dupes': dupes, 'wrong_sender': len(wrong),
            'recipient_status': dict(status), 'sent_email_rows': sent_rows, 'stage': dict(stage),
            'delivered_but_not_sent': sorted(delivered_to - sent_to), 'failed_but_delivered': sorted(failed_to & delivered_to),
            'marked_sent_not_delivered': sorted(sent_to - delivered_to)}


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * q))] if values else 0


# --------------------------------------------------------------------------- scenarios

def s_small():
    name = 'small'
    print('\n== small: 1 rep, 5 schools, production pacing (1s delay)')
    os.environ['OUTREACH_SEND_DELAY'] = '1.0'
    (uid, ids), = world(1, 5)
    M.queries = 0
    result = run_one(uid, ids)
    os.environ['OUTREACH_SEND_DELAY'] = '0'
    a = audit()
    f = result['final']
    check(name, 'batch accepted and finished', result['status_code'] == 202 and f and f['status'] == 'done')
    check(name, 'all 5 sent, none failed', f and (f['sent'], f['failed'], f['skipped']) == (5, 0, 0), str(f and (f['sent'], f['failed'])))
    check(name, 'SMTP received exactly 5, no duplicates', a['delivered'] == 5 and not a['dupes'])
    check(name, 'database matches SMTP', a['sent_email_rows'] == 5 and not a['delivered_but_not_sent'])
    check(name, 'schools advanced to contacted', a['stage'] == {'contacted': 5}, str(a['stage']))
    check(name, 'one SMTP connection reused', smtp.connections == 1, f'connections={smtp.connections}')
    print(f"  info  {result['secs']:.1f}s total, {M.queries / 5:.0f} queries per email")


def s_medium():
    name = 'medium'
    print('\n== medium: 1 rep, 50 schools, no pacing')
    (uid, ids), = world(1, 50)
    M.queries = 0
    result = run_one(uid, ids)
    a, f = audit(), result['final']
    check(name, 'all 50 sent exactly once', f and f['sent'] == 50 and a['delivered'] == 50 and not a['dupes'])
    check(name, 'database matches SMTP', a['sent_email_rows'] == 50 and not a['delivered_but_not_sent'])
    print(f"  info  {result['secs']:.1f}s ({50 / result['secs']:.1f}/s), {M.queries / 50:.0f} queries per email")


def s_heavy():
    name = 'heavy'
    print('\n== heavy: 1 rep, 500 schools (the batch maximum), no pacing')
    (uid, ids), = world(1, 500)
    M.queries = 0
    M.start_monitor()
    result = run_one(uid, ids)
    M.stop_monitor()
    a, f = audit(), result['final']
    check(name, 'all 500 sent exactly once', f and f['sent'] == 500 and a['delivered'] == 500 and not a['dupes'], str(f and f['sent']))
    check(name, 'database matches SMTP', a['sent_email_rows'] == 500 and not a['delivered_but_not_sent'])
    check(name, 'one SMTP connection for the whole batch', smtp.connections == 1, f'connections={smtp.connections}')
    check(name, 'no worker crashes logged', not catcher.records, '; '.join(catcher.records[:2]))
    with app.app_context():
        client = app.test_client()
        t = time.time()
        body = client.get(f'/api/outreach/batches/{f["id"]}', headers=headers(uid))
        print(f"  info  batch status payload: {len(body.data) / 1024:.0f} KB in {time.time() - t:.2f}s")
    print(f"  info  {result['secs']:.1f}s ({500 / result['secs']:.1f}/s), {M.queries / 500:.0f} queries per email, peak db conns {M.peak_conns}")
    per_email_s = result['secs'] / 500
    print(f"  info  projected at production pacing: delay 1s + {per_email_s:.2f}s local work "
          f"+ ~15 queries x db latency per email (50ms db => ~{1 + per_email_s + 15 * 0.05:.1f}s/email, "
          f"500 emails ~ {(1 + per_email_s + 15 * 0.05) * 500 / 60:.0f} min)")


def s_attachments():
    name = 'attachments'
    print('\n== attachments: 100 intro emails with the real PDFs attached')
    (uid, ids), = world(1, 100)
    M.queries = 0
    result = run_one(uid, ids, kind='initial', attachments=True)
    a, f = audit(), result['final']
    size = sum(d['bytes'] for d in smtp.delivered) / max(1, len(smtp.delivered)) / 1024
    check(name, 'all 100 sent', f and f['sent'] == 100 and a['delivered'] == 100 and not a['dupes'], str(f and f['sent']))
    print(f"  info  {result['secs']:.1f}s, average message {size:.0f} KB (PDFs encoded once and cached)")


def s_attach_mem():
    name = 'attach-mem'
    print('\n== attachment memory: 12 reps each sending 6 intro emails with the PDFs at the same time')
    import psutil
    specs = world(12, 6)
    proc, peak, stop = psutil.Process(), [0], threading.Event()
    baseline = proc.memory_info().rss

    def sample():
        while not stop.is_set():
            peak[0] = max(peak[0], proc.memory_info().rss)
            time.sleep(0.02)
    sampler = threading.Thread(target=sample)
    sampler.start()
    started = time.time()
    results = run_many(specs, attachments=True)
    secs = time.time() - started
    stop.set()
    sampler.join()
    a = audit()
    ok = all(r['final'] and r['final']['sent'] == 6 for r in results)
    check(name, 'all 72 attachment emails sent exactly once', ok and a['delivered'] == 72 and not a['dupes'], f"delivered={a['delivered']}")
    print(f"  info  {secs:.1f}s, peak memory +{(peak[0] - baseline) / 1048576:.0f} MB over idle ({peak[0] / 1048576:.0f} MB total)")


def s_limit():
    name = 'limit'
    print('\n== daily limit: 500 selected with a limit of 150, then a second batch')
    os.environ['OUTREACH_DAILY_LIMIT'] = '150'
    (uid, ids), = world(1, 500)
    first = run_one(uid, ids)
    a = audit()
    f = first['final']
    check(name, 'only 150 sent', a['delivered'] == 150 and f and f['sent'] == 150, str(a['delivered']))
    check(name, 'the other 350 skipped for the daily limit', f and f['skipped'] == 350, str(f and f['skipped']))
    second_ids = make_schools(uid, 10, offset=1000)
    client, response = post_batch(uid, second_ids)
    check(name, 'a second batch the same day is refused with 429', response.status_code == 429, str(response.status_code))
    os.environ['OUTREACH_DAILY_LIMIT'] = '100000'


def s_concurrency():
    name = 'concurrency'
    print('\n== concurrency: many reps sending at once at production pacing (1s delay), with a web user polling')
    os.environ['OUTREACH_SEND_DELAY'] = '1.0'
    for reps in (5, 15, 30):
        specs = world(reps, 8)
        probe_uid = make_rep(999)
        stop, latencies, errors = threading.Event(), [], []

        def probe():
            client, hdr = app.test_client(), headers(probe_uid)
            while not stop.is_set():
                t = time.time()
                try:
                    code = client.get('/api/outreach/limits', headers=hdr).status_code
                    if code != 200:
                        errors.append(code)
                except Exception as exc:
                    errors.append(type(exc).__name__)
                latencies.append(time.time() - t)
                time.sleep(0.3)
        prober = threading.Thread(target=probe)
        M.queries = 0
        M.start_monitor()
        prober.start()
        results = run_many(specs)
        stop.set()
        prober.join()
        M.stop_monitor()
        a = audit()
        finals = [r['final'] for r in results]
        done = sum(1 for f in finals if f and f['status'] == 'done' and f['sent'] == 8)
        print(f"  info  {reps} reps: peak db connections {M.peak_conns} ({M.peak_idle_tx} idle in transaction), "
              f"web p50 {pct(latencies, .5) * 1000:.0f}ms p95 {pct(latencies, .95) * 1000:.0f}ms max {max(latencies) * 1000:.0f}ms, "
              f"{len(errors)} web errors")
        check(name, f'{reps} reps: every batch finished with all 8 sent', done == reps, f'{done}/{reps}')
        check(name, f'{reps} reps: no duplicates or wrong sender', not a['dupes'] and a['wrong_sender'] == 0)
        check(name, f'{reps} reps: SMTP count matches database', a['delivered'] == reps * 8 and a['sent_email_rows'] == reps * 8,
              f"smtp={a['delivered']} db={a['sent_email_rows']}")
        check(name, f'{reps} reps: web requests stayed healthy (p95 < 2s, no errors)', not errors and pct(latencies, .95) < 2,
              f"errors={len(errors)} p95={pct(latencies, .95):.1f}s")
        check(name, f'{reps} reps: no worker crashes logged', not catcher.records, '; '.join(catcher.records[:1])[:160])
    os.environ['OUTREACH_SEND_DELAY'] = '0'


def s_faults():
    name = 'faults'
    print('\n== faults: bad recipients, provider quota, dropped connections, slow server')
    # a) hard rejects
    (uid, ids), = world(1, 50)
    smtp.reject = {f's{i}-u{uid}@school.test' for i in range(0, 50, 10)}
    f = run_one(uid, ids)['final']
    a = audit()
    check(name, 'rejected recipients fail, the rest are sent', f and (f['sent'], f['failed']) == (45, 5), str(f and (f['sent'], f['failed'])))
    smtp.reject = set()
    client = app.test_client()
    retry = client.post(f"/api/outreach/batches/{f['id']}/retry", headers=headers(uid))
    final = wait_batch(client, uid, f['id'])
    check(name, 'retry re-queues only the failed five and no one gets a second copy', retry.status_code == 202
          and retry.get_json()['requeued'] == 5 and final['sent'] == 50 and not audit()['dupes'])

    # b) provider quota mid-batch
    (uid, ids), = world(1, 50)
    smtp.quota_after = 20
    f = run_one(uid, ids)['final']
    check(name, 'quota stops the batch at 20 sent and fails the rest with a clear reason',
          f and f['sent'] == 20 and f['failed'] == 30 and 'limit' in (f['recipients'][-1]['error'] or '').lower(),
          str(f and (f['sent'], f['failed'])))
    smtp.quota_after = None
    client = app.test_client()
    retry = client.post(f"/api/outreach/batches/{f['id']}/retry", headers=headers(uid))
    final = wait_batch(client, uid, f['id'])
    check(name, 'after the quota clears, retry finishes the other 30 with no duplicates', final['sent'] == 50 and not audit()['dupes'])

    # c) connection dropped before the server accepted the message
    (uid, ids), = world(1, 20)
    smtp.drop_before = {7}
    f = run_one(uid, ids)['final']
    a = audit()
    check(name, 'drop before accept: never sent twice, the uncertain one is flagged unconfirmed and the rest continue',
          f and f['sent'] == 19 and f['unconfirmed'] == 1 and a['delivered'] == 19 and not a['dupes'],
          f"sent={f and f['sent']} unconfirmed={f and f['unconfirmed']} delivered={a['delivered']}")

    # d) connection dropped after the server accepted the message (reply lost)
    (uid, ids), = world(1, 20)
    smtp.drop_after = {7}
    f = run_one(uid, ids)['final']
    a = audit()
    check(name, 'drop after accept: the lost reply is flagged unconfirmed and never causes a second copy',
          not a['dupes'] and f and f['unconfirmed'] == 1 and a['delivered'] == 20, f"duplicates={a['dupes']} unconfirmed={f and f['unconfirmed']}")
    client = app.test_client()
    retry = client.post(f"/api/outreach/batches/{f['id']}/retry", headers=headers(uid))
    check(name, 'a plain retry does not resend the unconfirmed email', retry.status_code == 409 and not audit()['dupes'])

    # e) client times out while the server is still delivering
    (uid, ids), = world(1, 10)
    SMTP_TIMEOUT[0] = 1
    smtp.latency_at = {3: 2.5}
    f = run_one(uid, ids)['final']
    time.sleep(3)
    a = audit()
    SMTP_TIMEOUT[0] = 15
    check(name, 'timeout: a message that was delivered late is flagged unconfirmed, not failed, and not resent',
          not a['failed_but_delivered'] and not a['dupes'] and f and f['unconfirmed'] == 1,
          f"failed_but_delivered={a['failed_but_delivered']} dupes={a['dupes']}")

    # f) a slow provider
    (uid, ids), = world(1, 60)
    smtp.latency = 0.25
    result = run_one(uid, ids)
    a = audit()
    check(name, 'slow provider (250ms per message): all 60 delivered once', a['delivered'] == 60 and not a['dupes'])
    print(f"  info  {result['secs']:.1f}s for 60 emails at 250ms provider latency")


def s_crash():
    name = 'crash'
    print('\n== crash: the web process dies after the provider accepted an email but before it was recorded')
    (uid, ids), = world(1, 20)
    original, calls = outreach._record_success, itertools.count(1)

    def dying(*args, **kwargs):
        if next(calls) == 10:
            raise SystemExit
        return original(*args, **kwargs)
    outreach._record_success = dying
    client, response = post_batch(uid, ids)
    time.sleep(3)
    outreach._record_success = original
    with app.app_context():
        batch_id = response.get_json()['batch_id']
        before = {r.status: 0 for r in db.session.query(outreach.OutreachRecipient).all()}
        counts = Counter(r.status for r in db.session.query(outreach.OutreachRecipient).all())
        db.session.query(outreach.OutreachBatch).update({'heartbeat_at': service.utc_now() - timedelta(minutes=20)})
        db.session.commit()
    listing = client.get('/api/outreach/batches?limit=5', headers=headers(uid)).get_json()['items'][0]
    check(name, 'the dead batch is reported as stalled', listing['status'] == 'stalled', f"status={listing['status']} counts={dict(counts)}")
    retry = client.post(f'/api/outreach/batches/{batch_id}/retry', headers=headers(uid))
    final = wait_batch(client, uid, batch_id)
    a = audit()
    check(name, 'retry sends the 10 never-attempted emails and the 9 already sent stay sent',
          final and final['sent'] == 19 and final['unconfirmed'] == 1, str(final and (final['sent'], final['unconfirmed'])))
    check(name, 'the email in flight at the crash is not sent a second time', not a['dupes'], f"duplicates={a['dupes']}")


def s_double():
    name = 'double-submit'
    print('\n== double-submit: the same 20 schools posted twice at the same instant, and again after the first finished')
    (uid, ids), = world(1, 20)
    gate = threading.Barrier(2)
    results = [None, None]

    def go(i):
        gate.wait()
        results[i] = run_one(uid, ids)
    threads = [threading.Thread(target=go, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    a = audit()
    codes = sorted(r['status_code'] for r in results)
    check(name, 'simultaneous duplicate requests send each school once', a['delivered'] == 20 and not a['dupes'] and codes == [202, 400],
          f"codes={codes} delivered={a['delivered']} duplicated_schools={len(a['dupes'])}")
    again = run_one(uid, ids)
    a2 = audit()
    check(name, 'resubmitting after the first finished sends nothing new', a2['delivered'] == a['delivered'],
          f"status={again['status_code']} delivered {a['delivered']} -> {a2['delivered']}")


def s_cancel():
    name = 'cancel'
    print('\n== cancel: stop a 300-recipient batch about 1.5 seconds in')
    (uid, ids), = world(1, 300)
    smtp.latency = 0.02
    client, response = post_batch(uid, ids)
    batch_id = response.get_json()['batch_id']
    time.sleep(1.5)
    cancel = client.post(f'/api/outreach/batches/{batch_id}/cancel', headers=headers(uid))
    at_cancel = len(smtp.delivered)
    time.sleep(2)
    after = len(smtp.delivered)
    final = client.get(f'/api/outreach/batches/{batch_id}', headers=headers(uid)).get_json()
    check(name, 'cancel accepted', cancel.status_code == 200)
    check(name, 'at most one more email goes out after cancel', after - at_cancel <= 1, f'{at_cancel} -> {after}')
    check(name, 'counts add up (sent + cancelled = 300)', final['sent'] + final['cancelled'] == 300 and final['sent'] == after,
          f"sent={final['sent']} cancelled={final['cancelled']} smtp={after}")


SCENARIOS = {'small': s_small, 'medium': s_medium, 'heavy': s_heavy, 'attachments': s_attachments, 'attach-mem': s_attach_mem, 'limit': s_limit,
             'concurrency': s_concurrency, 'faults': s_faults, 'crash': s_crash, 'double': s_double, 'cancel': s_cancel}

if __name__ == '__main__':
    chosen = sys.argv[1:] or list(SCENARIOS)
    for key in chosen:
        try:
            SCENARIOS[key]()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            check(key, 'scenario ran without an exception', False, repr(exc)[:200])
    print('\n==== SUMMARY')
    for scenario, name, ok, detail in CHECKS:
        if not ok:
            print(f'FAIL [{scenario}] {name}  [{detail}]')
    print(f"{sum(1 for c in CHECKS if c[2])} passed, {sum(1 for c in CHECKS if not c[2])} failed of {len(CHECKS)}")
    with open(os.path.join(os.environ.get('TEMP', '.'), 'outreach_load_results.json'), 'w') as handle:
        json.dump([{'scenario': s, 'check': n, 'ok': o, 'detail': d} for s, n, o, d in CHECKS], handle, indent=1)
