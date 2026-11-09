"""Run only against a throwaway loopback Postgres named psa_ownership_test.
OWNERSHIP_TEST_DATABASE_URL=postgresql+psycopg2://.../psa_ownership_test python -B api/tests/check_templates_postgres.py
Destroys that database's public schema. No SMTP or production calls.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sys
from sqlalchemy import text
from sqlalchemy.engine import make_url

url = os.environ.get('OWNERSHIP_TEST_DATABASE_URL', '')
parsed = make_url(url)
if parsed.host not in ('127.0.0.1', 'localhost') or parsed.database != 'psa_ownership_test':
    raise SystemExit('Refusing: use a disposable loopback database named psa_ownership_test')
os.environ['DATABASE_URL'] = url
os.environ['JWT_SECRET_KEY'] = 'ownership-test-only'
os.environ['MAIL_CREDENTIAL_KEY'] = base64.urlsafe_b64encode(b'0' * 32).decode()
os.environ['PSA_DISABLE_SCHEDULER'] = 'true'
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api import api as service

db = service.db
with service.app.app_context():
    engine=db.engine
    with engine.begin() as connection:
        connection.execute(text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))
    db.metadata.create_all(engine,tables=[table for name,table in db.metadata.tables.items() if name!='school_assignment_reviews'])
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE sales_schools ALTER COLUMN user_id SET NOT NULL'))
        connection.execute(text('ALTER TABLE sales_schools DROP COLUMN ownership_version'))
        connection.execute(text('ALTER TABLE outreach_recipients DROP COLUMN ownership_version'))
        for role in ('anon','authenticated'):
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role}; END IF; END $$"))
    migration=(Path(__file__).resolve().parents[1]/'migrations/20261105_school_ownership.sql').read_text()
    for _ in range(2):
        raw=engine.raw_connection()
        try:
            cursor=raw.cursor();cursor.execute(migration);raw.commit();cursor.close()
        finally: raw.close()
    assert db.session.execute(text("SELECT relrowsecurity FROM pg_class WHERE relname='school_assignment_reviews'")).scalar()
    for role in ('anon','authenticated'):
        for privilege in ('SELECT','INSERT','UPDATE','DELETE'):
            assert not db.session.execute(text("SELECT has_table_privilege(:role,'school_assignment_reviews',:privilege)"),dict(role=role,privilege=privilege)).scalar()
    admin=service.User(name='Admin',email='admin@example.test',admin=True,password_hash='x')
    left=service.User(name='Rep A',email='a@example.test',admin=False,password_hash='x')
    right=service.User(name='Rep B',email='b@example.test',admin=False,password_hash='x')
    db.session.add_all([admin,left,right]);db.session.commit()
    admin_id,left_id,right_id=admin.id,left.id,right.id
    tokens={u.id:service.create_access_token(identity=str(u.id)) for u in (admin,left,right)}
    school=service.SalesSchool(school_name='Claim Race',email='claim@example.test',school_type='elementary',user_id=None,status='pending')
    db.session.add(school);db.session.commit();sid=school.id

service.app.config['TESTING']=True
def post(path,data,uid=admin_id):
    with service.app.test_client() as client:
        response=client.post(path,json=data,headers={'Authorization':'Bearer '+tokens[uid]})
        return response.status_code,response.get_json()
with ThreadPoolExecutor(2) as pool:
    results=list(pool.map(lambda uid:post(f'/api/crm/schools/{sid}/claim',{},uid),[left_id,right_id]))
assert sorted(r[0] for r in results)==[200,409],results
preview=post('/api/crm/schools/assignment-preview',{'ids':[sid],'user_id':None})[1]
path=f"/api/crm/schools/assignment-reviews/{preview['id']}/commit"
with ThreadPoolExecutor(2) as pool:
    results=list(pool.map(lambda _:post(path,{}),[1,2]))
assert [r[0] for r in results]==[200,200] and results[0][1]==results[1][1],results
plans=[post('/api/crm/schools/assignment-preview',{'ids':[sid],'user_id':uid})[1] for uid in (left_id,right_id)]
with ThreadPoolExecutor(2) as pool:
    results=list(pool.map(lambda plan:post(f"/api/crm/schools/assignment-reviews/{plan['id']}/commit",{}),plans))
assert sorted(r[0] for r in results)==[200,409],results
with service.app.app_context():
    # Core insert avoids incidental contact synchronization in this assignment-only load test.
    db.session.execute(service.SalesSchool.__table__.insert(),[dict(school_name=f'Scale School {i}',email=f'scale{i}@example.test',school_type='elementary',status='pending',user_id=left_id,county='Scale County') for i in range(2000)])
    db.session.commit()
plan=post('/api/crm/schools/assignment-preview',{'filters':{'county':'Scale County'},'user_id':right_id})[1]
assert plan['total']==2000,plan
from sqlalchemy import event
import time
queries=[]
def count(*args): queries.append(1)
event.listen(engine,'before_cursor_execute',count)
start=time.monotonic()
try:
    result=post(f"/api/crm/schools/assignment-reviews/{plan['id']}/commit",{})
finally: event.remove(engine,'before_cursor_execute',count)
assert result[0]==200 and result[1]['updated']==2000,result
assert len(queries)<100, len(queries)
with service.app.app_context():
    assert service.SalesSchool.query.filter_by(county='Scale County',user_id=right_id).count()==2000
    assert service.SchoolActivity.query.filter_by(kind='ownership').count()==2003
    db.session.remove();db.engine.dispose()
print(f'Ownership Postgres passed: migration twice, RLS, competing claims, idempotent commits, conflicting reviews; 2000-school assignment {time.monotonic()-start:.2f}s, {len(queries)} SQL statements (local only). No SMTP.')
