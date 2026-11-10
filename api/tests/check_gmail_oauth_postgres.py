"""Guarded disposable PostgreSQL OAuth race check. Google HTTP is always fake."""
import base64
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

from sqlalchemy import text
from sqlalchemy.engine import make_url

url = os.environ.get('GMAIL_OAUTH_TEST_DATABASE_URL', '')
parsed = make_url(url)
if parsed.host not in ('127.0.0.1', 'localhost') or parsed.database != 'psa_gmail_oauth_test':
    raise SystemExit('Use only disposable loopback database psa_gmail_oauth_test')
os.environ.update(DATABASE_URL=url, JWT_SECRET_KEY='local-oauth-test', PSA_DISABLE_SCHEDULER='true',
    OUTREACH_WORKER_MODE='external', GMAIL_OAUTH_ENABLED='true', GMAIL_OAUTH_CLIENT_ID='local-client',
    GMAIL_OAUTH_CLIENT_SECRET='fake-secret', GMAIL_OAUTH_REDIRECT_URI='https://api.example.test/api/mail/google/callback')
os.environ.setdefault('MAIL_CREDENTIAL_KEY', base64.urlsafe_b64encode(b'0' * 32).decode())
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api import api as svc, gmail_oauth

app, db = svc.app, svc.db
tables = {'gmail_connections', 'gmail_authorizations'}
try:
    with app.app_context():
        with db.engine.begin() as conn:
            conn.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
            for role in ('anon', 'authenticated'):
                conn.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
        db.metadata.create_all(db.engine, tables=[t for n, t in db.metadata.tables.items() if n not in tables])
        sql = (Path(__file__).resolve().parents[1] / 'migrations/20261109_gmail_oauth.sql').read_text()
        for _ in range(2):
            raw = db.engine.raw_connection()
            try:
                with raw.cursor() as cursor: cursor.execute(sql)
                raw.commit()
            finally: raw.close()
        for name in tables:
            assert db.session.execute(text('SELECT relrowsecurity FROM pg_class WHERE relname=:name'), {'name': name}).scalar()
            for role in ('anon', 'authenticated'):
                for permission in ('SELECT', 'INSERT', 'UPDATE', 'DELETE'):
                    assert not db.session.execute(text('SELECT has_table_privilege(:role,:name,:permission)'),
                        dict(role=role, name=name, permission=permission)).scalar()
        user = svc.User(name='Local OAuth', email='oauth@example.test', password_hash='x')
        db.session.add(user); db.session.commit(); uid = user.id
        headers = {'Authorization': 'Bearer ' + svc.create_access_token(identity=str(uid))}
    with app.test_client() as client:
        result = client.post('/api/mail/google/connect', headers=headers)
        assert result.status_code == 200, result.get_json()
        state = parse_qs(urlsplit(result.get_json()['authorization_url']).query)['state'][0]
    def callback(_):
        with app.test_client() as client:
            return client.get('/api/mail/google/callback', query_string={'state': state, 'code': 'fake-code'}).status_code
    token = Mock(status_code=200, json=Mock(return_value=dict(access_token='fake-access', refresh_token='fake-refresh', scope=' '.join(gmail_oauth.SCOPES))))
    profile = Mock(status_code=200, json=Mock(return_value={'emailAddress': 'oauth@example.test'}))
    with patch.object(gmail_oauth.requests, 'post', return_value=token) as post, patch.object(gmail_oauth.requests, 'get', return_value=profile):
        with ThreadPoolExecutor(max_workers=4) as executor: statuses = list(executor.map(callback, range(4)))
        assert statuses.count(200) == 1 and statuses.count(400) == 3, statuses
        assert post.call_count == 1
    with app.app_context():
        connection = db.session.get(svc.GmailConnection, uid)
        assert svc.decrypt_password(connection.refresh_token_cipher) == 'fake-refresh'
        assert not connection.active
    print('PASS: migration twice, RLS/public privileges, four concurrent callbacks produce one token exchange and one encrypted inactive connection. No Google or real mail.')
finally:
    with app.app_context(): db.session.remove(); db.engine.dispose()
