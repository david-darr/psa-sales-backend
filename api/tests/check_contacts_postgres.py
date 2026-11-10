"""Standalone destructive integration test: ONLY a disposable local Postgres DB.

Run from repo root: python -B api/tests/check_contacts_postgres.py
Set CONTACT_TEST_DATABASE_URL to a loopback database named psa_contacts_test.
No SMTP is called. Never use a production connection string here.
"""
import base64
import csv
from concurrent.futures import ThreadPoolExecutor
import io
import os
from pathlib import Path
import sys
import time

from sqlalchemy import event, text
from sqlalchemy.engine import make_url

url = os.environ.get('CONTACT_TEST_DATABASE_URL', '')
parsed = make_url(url)
if parsed.host not in ('127.0.0.1', 'localhost') or parsed.database != 'psa_contacts_test':
    raise SystemExit('Refusing: use a disposable loopback database named psa_contacts_test')
os.environ['DATABASE_URL'] = url
os.environ['JWT_SECRET_KEY'] = 'contact-test-only'
os.environ['MAIL_CREDENTIAL_KEY'] = base64.urlsafe_b64encode(b'0' * 32).decode()
os.environ['PSA_DISABLE_SCHEDULER'] = 'true'
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api import api as service  # noqa: E402

db = service.db
with service.app.app_context():
    engine = db.engine
    with engine.begin() as connection:
        connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
    excluded = {'contacts', 'school_contacts', 'contact_events', 'contact_imports', 'contact_import_guard'}
    db.metadata.create_all(engine, tables=[table for name, table in db.metadata.tables.items() if name not in excluded])
    with engine.begin() as connection:
        for role in ('anon', 'authenticated'):
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
        connection.execute(service.User.__table__.insert().values(id=1, name='Test Rep', email='rep@example.test', password_hash='x', admin=True))
        connection.execute(service.SalesSchool.__table__.insert(), [
            dict(id=1, school_name='First School', email='primary@example.test', additional_emails='["SHARED@example.test"]', contact_name='Alex', user_id=1),
            dict(id=2, school_name='Sister School', email='shared@example.test', additional_emails='[]', contact_name='', user_id=1),
            dict(id=3, school_name='Old Malformed Data', email='bad', additional_emails='not-json', contact_name='', user_id=1),
        ])
        connection.execute(service.SchoolActivity.__table__.insert().values(sales_school_id=1, actor_id=1, kind='unsubscribed', detail='Legacy opt-out'))
        connection.execute(text("select setval(pg_get_serial_sequence('sales_schools','id'), 3)"))
        connection.execute(text("select setval(pg_get_serial_sequence('users','id'), 1)"))
    migration = (Path(__file__).resolve().parents[1] / 'migrations/20261105_contacts.sql').read_text()
    for _ in range(2):
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor(); cursor.execute(migration); raw.commit(); cursor.close()
        finally:
            raw.close()
    assert service.Contact.query.count() == 2
    assert service.Contact.query.filter_by(do_not_contact=True).count() == 2
    assert service.SchoolContact.query.count() == 3
    assert service.SchoolContact.query.filter_by(name='Alex').count() == 1
    assert db.session.execute(text("select bool_and(relrowsecurity) from pg_class where relname in ('contacts','school_contacts','contact_events','contact_imports','contact_import_guard')")).scalar()
    assert db.session.execute(text("select count(*) from information_schema.role_table_grants where grantee in ('anon','authenticated') and table_name in ('contacts','school_contacts','contact_events','contact_imports','contact_import_guard')")).scalar() == 0
    token = service.create_access_token(identity='1')

headers = {'Authorization': 'Bearer ' + token}
service.app.config['TESTING'] = True


def preview(name):
    with service.app.test_client() as client:
        response = client.post('/api/contact-imports/preview', headers=headers,
            data={'file': (io.BytesIO(f'school_name,email,address\n{name},new@example.test,{name} Rd\n{name},second@example.test,{name} Rd\n'.encode()), 'contacts.csv')})
        assert response.status_code == 200, response.get_json()
        return response.get_json()


def commit(plan):
    with service.app.test_client() as client:
        response = client.post(f'/api/contact-imports/{plan["id"]}/commit', headers=headers, json={'file_hash': plan['file_hash']})
        return response.status_code, response.get_json()


first = preview('Birch Grove')
with ThreadPoolExecutor(2) as pool:
    results = list(pool.map(commit, [first, first]))
assert [r[0] for r in results] == [200, 200], results
assert results[0][1] == results[1][1], results
assert results[0][1]['contacts_added'] == 2, results
left, right = preview('Riverton'), preview('Riverton')
with ThreadPoolExecutor(2) as pool:
    results = list(pool.map(commit, [left, right]))
assert sorted(r[0] for r in results) == [200, 409], results
with service.app.app_context():
    assert service.SalesSchool.query.filter_by(school_name='Birch Grove').count() == 1
    assert service.SalesSchool.query.filter_by(school_name='Riverton').count() == 1
buffer = io.StringIO()
writer = csv.writer(buffer)
writer.writerow(['school_name','email','address','contact_role','school_type'])
for n in range(410):
    i = n % 145
    writer.writerow([f'Load Campus {i:03d} {i*1237}', f'load{n}@example.test', f'{i} Education Way', 'pta_pto' if n % 2 else 'principal_ap', 'elementary'])
with service.app.test_client() as client:
    plan = client.post('/api/contact-imports/preview', headers=headers, data={'file': (io.BytesIO(buffer.getvalue().encode()),'load.csv')}).get_json()
    decisions = {group['key']: {'action':'new'} for group in plan['groups'] if group['action']=='conflict'}
    queries = []
    def count_query(*args):
        queries.append(1)
    event.listen(engine,'before_cursor_execute', count_query)
    started = time.monotonic()
    try:
        response = client.post(f'/api/contact-imports/{plan["id"]}/commit', headers=headers, json={'file_hash':plan['file_hash'],'decisions':decisions})
    finally:
        event.remove(engine,'before_cursor_execute',count_query)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['schools_added'] == 145, response.get_json()
    assert response.get_json()['contacts_added'] == 410, response.get_json()
    print(f'Postgres 145-school/410-contact commit: {time.monotonic()-started:.2f}s, {len(queries)} statements (local DB; not Supabase latency).')
with service.app.test_client() as client:
    contact = client.get('/api/sales-schools/1/contacts',headers=headers).get_json()['contacts'][0]
    response = client.patch(f'/api/sales-schools/1/contacts/{contact["id"]}',headers=headers,json={
        'version':contact['version'],'contact_version':contact['contact_version'],
        'do_not_contact':True,'suppression_reason':'Confirmed existing opt-out'})
    assert response.status_code == 200, response.get_json()
    response = client.post('/api/crm/schools/delete',headers=headers,json={'ids':[1]})
    assert response.status_code == 200, response.get_json()
with service.app.app_context():
    assert service.SchoolContact.query.filter_by(school_id=1).count() == 0
    assert service.Contact.query.filter_by(email=contact['email'],do_not_contact=True).count() == 1
    assert service.ContactEvent.query.filter_by(school_id=None).count() >= 1
print('Postgres contacts passed: rerunnable migration, malformed-JSON backfill, shared mailboxes, preserved opt-outs, RLS/grants, concurrent commits and conflicting previews.')
