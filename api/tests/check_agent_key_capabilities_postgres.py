"""Upgrade the original key CHECK, then run the real native connection flow.

Only a disposable loopback PostgreSQL database and fake employee are accepted.
No production login, remote HTTP, mailbox traffic or real emails.
"""
import base64
import importlib
import os
import sys
import tempfile
import types
import zipfile
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.engine import make_url

url=os.environ.get('AGENT_KEY_TEST_DATABASE_URL','')
parsed=make_url(url)
if parsed.host not in ('127.0.0.1','localhost') or parsed.database!='psa_agent_key_test':
    raise SystemExit('Use only disposable loopback database psa_agent_key_test')
os.environ.update(DATABASE_URL=url,JWT_SECRET_KEY='local-agent-key',PSA_DISABLE_SCHEDULER='true',OUTREACH_WORKER_MODE='external')
os.environ.setdefault('MAIL_CREDENTIAL_KEY',base64.urlsafe_b64encode(b'0'*32).decode())
root=Path(__file__).resolve().parents[2];sys.path.insert(0,str(root))
from api import api as svc,agent_api

class Storage:
    def __init__(self):self.data={}
    def read_json(self,name,default):return self.data.get(name,default)
    def write_json(self,name,value):self.data[name]=value
    def encrypt(self,value):return 'fake-encrypted:'+base64.b64encode(value.encode()).decode()
    def decrypt(self,value):return base64.b64decode(value.removeprefix('fake-encrypted:')).decode()

app,db=svc.app,svc.db
bundle=tempfile.TemporaryDirectory(prefix='psa-key-fixture-')
try:
    with app.app_context():
        with db.engine.begin() as conn:
            conn.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
            for role in ('anon','authenticated'):
                conn.execute(text(f"DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
        svc.User.__table__.create(db.engine)
        def migrate(name):
            raw=db.engine.raw_connection()
            try:
                with raw.cursor() as cursor:cursor.execute((root/'api/migrations'/name).read_text(encoding='utf-8'))
                raw.commit()
            finally:raw.close()
        migrate('20261030_agent_api_keys.sql')
        db.create_all()
        user=svc.User(name='Native fixture',email='fixture@example.test',admin=True)
        user.set_password('Only-a-local-fixture');db.session.add(user);db.session.flush()
        legacy=svc.AgentApiKey(user_id=user.id,name='Existing key',key_hash='a'*64,key_hint='fixture',scopes='read',expires_at=svc.utc_now()+timedelta(days=30))
        db.session.add(legacy);db.session.commit();uid,oldid=user.id,legacy.id
        jwt={'Authorization':'Bearer '+svc.create_access_token(identity=str(uid))}
        with app.test_client() as client:
            rejected=client.post('/api/agent-keys',headers=jwt,json=dict(name='New permissions',scope='read',expires_in_days=30,capabilities=['outreach:read']))
            assert rejected.status_code==503,rejected.status_code
        for _ in range(2):migrate('20261110_agent_key_capabilities.sql')
        assert db.session.get(svc.AgentApiKey,oldid).scopes=='read'
    with zipfile.ZipFile(root/'integrations/kairos/psa_command.zip') as archive:archive.extractall(bundle.name)
    package=types.ModuleType('native_key_fixture');package.__path__=[str(Path(bundle.name)/'psa_command')];sys.modules[package.__name__]=package
    native=importlib.import_module('native_key_fixture.human_session')
    storage=Storage();saved={};calls=[]
    def save(user,system,url,key):saved[user]=(url,storage.encrypt(key))
    def transport(method,url,headers,body):
        parsed=urlsplit(url);assert parsed.hostname=='127.0.0.1'
        calls.append((method,parsed.path))
        with app.test_client() as client:
            response=client.open(parsed.path,method=method,headers=headers,json=body)
            return response.status_code,response.get_json()
    broker=native.HumanSession(storage,save,transport=transport)
    result=broker.connect('local-owner','http://127.0.0.1:5000/api/agent/v1',
        'fixture@example.test','Only-a-local-fixture',list(agent_api.CAPABILITIES),scope='write',confirm_send=True)
    assert result['connected'] and set(result['capabilities'])==set(agent_api.CAPABILITIES)
    assert calls[:2]==[('POST','/api/login'),('POST','/api/agent-keys')]
    assert storage.read_json('human-session.json',{})['local-owner']['token'].startswith('fake-encrypted:')
    with app.app_context():
        assert svc.AgentApiKey.query.count()==2
        assert db.session.get(svc.AgentApiKey,oldid).scopes=='read'
        for role in ('anon','authenticated'):
            assert not db.session.execute(text("select has_table_privilege(:r,'public.agent_api_keys','SELECT')"),dict(r=role)).scalar()
    print('PASS: original PostgreSQL CHECK reproduced rejection; repair twice preserved old key; complete native sign-in/key creation with every optional permission succeeded; private session encrypted, public access unchanged. No production credentials or real mail.')
finally:
    with app.app_context():db.session.remove();db.engine.dispose()
    bundle.cleanup()
