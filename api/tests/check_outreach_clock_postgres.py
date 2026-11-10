"""Disposable Supabase Postgres/Vault/cron check. Never contacts production."""
import base64
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock,patch
from sqlalchemy import text
from sqlalchemy.engine import make_url

url=os.environ.get('OUTREACH_CLOCK_TEST_DATABASE_URL','')
parsed=make_url(url)
if parsed.host not in ('127.0.0.1','localhost') or parsed.database!='psa_clock_test':
    raise SystemExit('Use only disposable loopback database psa_clock_test with pg_cron/pg_net/Vault available')
os.environ.update(DATABASE_URL=url,JWT_SECRET_KEY='local-clock',PSA_DISABLE_SCHEDULER='true',OUTREACH_WORKER_MODE='external')
os.environ.setdefault('MAIL_CREDENTIAL_KEY',base64.urlsafe_b64encode(b'0'*32).decode())
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from api import api as svc,outreach

app,db=svc.app,svc.db
try:
    with app.app_context():
        db.create_all()
        with db.engine.begin() as c:
            for role in ('anon','authenticated'):
                c.execute(text(f"DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
            c.execute(text('CREATE EXTENSION IF NOT EXISTS supabase_vault CASCADE'))
        base=Path(__file__).resolve().parents[1]
        for source in (base/'migrations/20261110_outreach_clock.sql',base/'maintenance/install_outreach_clock.sql'):
            sql=source.read_text(encoding='utf-8').replace('https://psa-sales-backend.onrender.com/api/internal/outreach/wake','http://127.0.0.1:9/wake')
            for _ in range(2):
                raw=db.engine.raw_connection()
                try:
                    with raw.cursor() as cursor:cursor.execute(sql)
                    raw.commit()
                finally:raw.close()
        assert not db.session.execute(text("select active from cron.job where jobname='psa-outreach-clock'")).scalar()
        assert db.session.execute(text('select public.psa_outreach_clock()')).scalar() is None
        token=db.session.execute(text("select decrypted_secret from vault.decrypted_secrets where name='psa_outreach_clock'")).scalar()
        assert len(token)==64
        for role in ('anon','authenticated'):
            assert not db.session.execute(text("select has_function_privilege(:r,'public.psa_outreach_clock()','EXECUTE')"),dict(r=role)).scalar()
            assert not db.session.execute(text("select has_table_privilege(:r,'public.outreach_clock_credentials','SELECT')"),dict(r=role)).scalar()
        user=svc.User(name='Clock fixture',email='clock@example.test',password_hash='x')
        db.session.add(user);db.session.flush()
        db.session.add(outreach.OutreachBatch(user_id=user.id,kind='test',status='queued'))
        db.session.commit()
        request_id=db.session.execute(text('select public.psa_outreach_clock()')).scalar()
        assert request_id is not None
        db.session.commit()
    worker=Mock()
    def wake(_):
        with app.test_client() as client:
            response=client.post('/api/internal/outreach/wake',headers={'Authorization':'Bearer '+token},json={})
            assert response.status_code==202,response.status_code
            return response.get_json()['accepted']
    with patch.dict(app.extensions,{'psa_web_outreach_worker':worker}):
        with ThreadPoolExecutor(max_workers=4) as executor:claims=list(executor.map(wake,range(4)))
        assert sum(claims)==1,claims
        worker.start.assert_called_once_with()
    print('PASS: idempotent disabled cron/Vault install, no idle HTTP, due-work trigger to loopback only, protected tables/function, four concurrent authenticated wake requests claim once. No production or real mail.')
finally:
    with app.app_context():db.session.remove();db.engine.dispose()
