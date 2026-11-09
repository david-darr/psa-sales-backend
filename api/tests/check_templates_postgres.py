"""Run only against a throwaway loopback Postgres named psa_templates_test.
TEMPLATE_TEST_DATABASE_URL=postgresql+psycopg2://.../psa_templates_test python -B api/tests/check_templates_postgres.py
Destroys that database's public schema. No SMTP or production calls.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sys
from sqlalchemy import text
from sqlalchemy.engine import make_url

url = os.environ.get('TEMPLATE_TEST_DATABASE_URL', '')
parsed = make_url(url)
if parsed.host not in ('127.0.0.1', 'localhost') or parsed.database != 'psa_templates_test':
    raise SystemExit('Refusing: use a disposable loopback database named psa_templates_test')
os.environ['DATABASE_URL'] = url
os.environ['JWT_SECRET_KEY'] = 'template-test-only'
os.environ['MAIL_CREDENTIAL_KEY'] = base64.urlsafe_b64encode(b'0' * 32).decode()
os.environ['PSA_DISABLE_SCHEDULER'] = 'true'
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api import api as service

db = service.db
with service.app.app_context():
    engine = db.engine
    with engine.begin() as connection:
        connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
    db.metadata.create_all(engine, tables=[table for name, table in db.metadata.tables.items() if name not in ('mail_templates','mail_template_versions','mail_template_assets','mail_template_imports')])
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE outreach_batches DROP COLUMN template_snapshot'))
        for role in ('anon', 'authenticated'):
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
    migration = (Path(__file__).resolve().parents[1] / 'migrations/20261105_shared_templates.sql').read_text()
    for _ in range(2):
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor(); cursor.execute(migration); raw.commit(); cursor.close()
        finally:
            raw.close()
    assert db.session.execute(text("SELECT bool_and(relrowsecurity) FROM pg_class WHERE relname IN ('mail_templates','mail_template_versions','mail_template_assets','mail_template_imports')")).scalar()
    for role in ('anon', 'authenticated'):
        for table in ('mail_templates', 'mail_template_versions', 'mail_template_assets', 'mail_template_imports'):
            for privilege in ('SELECT','INSERT','UPDATE','DELETE'):
                assert not db.session.execute(text('SELECT has_table_privilege(:role,:table,:privilege)'), dict(role=role,table=table,privilege=privilege)).scalar()
            if table not in ('mail_template_assets','mail_template_imports'):
                assert not db.session.execute(text("SELECT has_sequence_privilege(:role,:seq,'USAGE')"),dict(role=role,seq=table+'_id_seq')).scalar()
    actor = service.User(name='Template Admin',email='admin@example.test',admin=True,password_hash='x')
    db.session.add(actor); db.session.commit()
    token = service.create_access_token(identity=str(actor.id))

headers = {'Authorization':'Bearer '+token}
service.app.config['TESTING'] = True

def seed(_):
    with service.app.test_client() as client:
        response = client.post('/api/outreach/templates/seed-winter-2027',headers=headers)
        assert response.status_code == 200, response.get_json()
        return response.get_json()

with ThreadPoolExecutor(2) as pool:
    results = list(pool.map(seed,[1,2]))
assert sum(result['added'] for result in results) == 16, results
with service.app.test_client() as client:
    items = client.get('/api/outreach/templates',headers=headers).get_json()['items']
assert len(items) == 16
original = items[0]

def edit(name):
    with service.app.test_client() as client:
        response = client.put(f"/api/outreach/templates/{original['id']}",headers=headers,json={**original,'name':name})
        return response.status_code

with ThreadPoolExecutor(2) as pool:
    statuses = list(pool.map(edit,['Admin A update','Admin B update']))
assert sorted(statuses) == [200,409], statuses
with service.app.app_context():
    assert service.MailTemplate.query.count() == 16
    assert service.MailTemplateVersion.query.count() == 17
    versions = service.MailTemplateVersion.query.filter_by(template_id=original['id']).order_by(service.MailTemplateVersion.revision).all()
    import json
    assert json.loads(versions[0].snapshot)['name'] == original['name']
    assert json.loads(versions[1].snapshot)['name'] in ('Admin A update','Admin B update')
    import hashlib, base64
    payload = b'%PDF-1.4\nLocal template attachment'
    asset_id = hashlib.sha256(payload).hexdigest()
    db.session.add(service.TemplateAsset(id=asset_id, name='Test.pdf', payload=payload))
    db.session.commit()
    before = db.engine.pool.checkedout()
    name, encoded = service.template_attachment_payload(asset_id)
    assert name == 'Test.pdf' and base64.decodebytes(encoded.encode()) == payload
    assert db.engine.pool.checkedout() == before, 'Attachment reads must release their DB connection before SMTP'
    db.session.remove(); db.engine.dispose()
# Concurrent JSON imports use stable source keys and cannot duplicate shared templates.
import io
row = dict(name='Uploaded JSON',kind='initial',step=0,audience='general',subject='Hello {school name}',body='Hello from {my name}')
def preview_import(_):
    with service.app.test_client() as client:
        response=client.post('/api/outreach/template-imports/preview',headers=headers,data={'file':(io.BytesIO(json.dumps(row).encode()),'templates.json')})
        assert response.status_code==200,response.get_json()
        return response.get_json()['id']
with ThreadPoolExecutor(2) as pool:
    review_ids=list(pool.map(preview_import,[1,2]))
def commit_import(rid):
    with service.app.test_client() as client:
        response=client.post(f'/api/outreach/template-imports/{rid}/commit',headers=headers,json={})
        assert response.status_code==200,response.get_json()
        return response.get_json()
with ThreadPoolExecutor(2) as pool:
    results=list(pool.map(commit_import,review_ids))
assert sum(result['added'] for result in results)==1,results
assert commit_import(review_ids[0])==results[0]
with service.app.app_context():
    assert service.MailTemplate.query.count()==17
    db.session.remove();db.engine.dispose()
print('Postgres template checks passed: migration twice, private grants, concurrent seed/import idempotence, conflicting edits, immutable PDFs and connection release. No SMTP.')
