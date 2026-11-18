"""Destructive integration check, ONLY for an empty disposable localhost database.

Set PSA_WORKSPACE_TEST_DATABASE_URL to a local PostgreSQL database whose name
starts psa_workspace_test. Never uses DATABASE_URL or the linked Supabase DB.
"""
import base64
import os
from pathlib import Path

from sqlalchemy.engine import make_url


def main():
    url = os.environ['PSA_WORKSPACE_TEST_DATABASE_URL']
    target = make_url(url)
    assert target.host in ('127.0.0.1', 'localhost'), 'Disposable localhost only'
    assert target.database.startswith('psa_workspace_test'), 'Disposable database name required'
    os.environ.update(DATABASE_URL=url, JWT_SECRET_KEY='workspace-local-test-only', OUTREACH_WORKER_MODE='external',
                      PSA_DISABLE_SCHEDULER='true', MAIL_CREDENTIAL_KEY=base64.urlsafe_b64encode(b'0' * 32).decode())
    from api import api as svc
    from api.sales_workspaces import TABLES
    with svc.app.app_context():
        svc.db.create_all()
        assert svc.User.query.count() == 0, 'Database must be empty'
        with svc.db.engine.begin() as conn:
            for table in TABLES:
                conn.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN sales_workspace CASCADE')
            conn.exec_driver_sql('ALTER TABLE sales_schools DROP COLUMN industry, DROP COLUMN sponsorship_value')
            conn.exec_driver_sql("INSERT INTO users(id,name,email,admin,password_hash) VALUES(1,'Fixture admin','admin@example.test',true,'not-a-login')")
            conn.exec_driver_sql("INSERT INTO sales_schools(id,school_name,email,school_type,status,user_id,ownership_version) VALUES(1,'Existing School','school@example.test','elementary','contacted',1,0)")
            conn.exec_driver_sql("SELECT setval(pg_get_serial_sequence('sales_schools','id'),1)")
            conn.exec_driver_sql('ALTER TABLE sales_schools ENABLE ROW LEVEL SECURITY')
        migration = (Path(__file__).parents[1] / 'migrations/20261112_school_business_sales.sql').read_text()
        for _ in range(2):
            connection = svc.db.engine.raw_connection()
            try:
                with connection.cursor() as cursor:
                    cursor.execute(migration)
                connection.commit()
            finally:
                connection.close()
        with svc.db.engine.connect() as conn:
            assert tuple(conn.exec_driver_sql('SELECT school_name,sales_workspace FROM sales_schools WHERE id=1').one()) == ('Existing School', 'school')
            assert conn.exec_driver_sql("SELECT relrowsecurity FROM pg_class WHERE oid='sales_schools'::regclass").scalar() is True
            assert conn.exec_driver_sql("SELECT count(*) FROM pg_constraint WHERE position('_sales_workspace_check' in conname) > 0").scalar() == len(TABLES)
        business = svc.SalesSchool(school_name='Business fixture',email='business@example.test',school_type='business',sales_workspace='business',user_id=1,status='partner',sponsorship_value=2500)
        svc.db.session.add(business); svc.db.session.commit()
        token = svc.create_access_token(identity='1')
        client = svc.app.test_client()
        for area, expected in [('school','Existing School'),('business','Business fixture')]:
            headers = {'Authorization':'Bearer '+token,'X-PSA-Workspace':area}
            response = client.get('/api/crm/schools',headers=headers)
            assert response.status_code == 200, response.get_json()
            assert [r['school_name'] for r in response.get_json()['items']] == [expected]
            assert client.get('/api/crm/overview',headers=headers).get_json()['schools'] == 1
        svc.db.session.remove()
        # Checklist migration on an old schema, then idempotent re-application.
        with svc.db.engine.begin() as conn:
            conn.exec_driver_sql('DROP TABLE taskbar_pending_assignments')
            conn.exec_driver_sql('ALTER TABLE outreach_batches DROP COLUMN audience')
            conn.exec_driver_sql("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon; END IF; IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated; END IF; END $$")
        checklist=(Path(__file__).parents[1]/'migrations/20261118_psa_checklist.sql').read_text(encoding='utf-8-sig')
        for _ in range(2):
            connection=svc.db.engine.raw_connection()
            try:
                with connection.cursor() as cursor:cursor.execute(checklist)
                connection.commit()
            finally:connection.close()
        with svc.db.engine.connect() as conn:
            assert conn.exec_driver_sql("SELECT relrowsecurity FROM pg_class WHERE oid='taskbar_pending_assignments'::regclass").scalar() is True
            assert not conn.exec_driver_sql("SELECT has_table_privilege('anon','taskbar_pending_assignments','SELECT')").scalar()
        first=svc.SalesSchool(school_name='Merge fixture',email='merge@example.test',school_type='elementary',status='pending',user_id=1)
        second=svc.SalesSchool(school_name='Merge fixture',email='merge@example.test',school_type='elementary',status='pending',user_id=1)
        svc.db.session.add_all([first,second]);svc.db.session.commit()
        first_id,second_id=first.id,second.id
        svc.db.session.add(svc.SalesTask(title='Follow up',user_id=1,school_id=first_id,priority='low'))
        svc.db.session.commit()
        headers={'Authorization':'Bearer '+token}
        body=dict(source_id=first_id,target_id=second_id)
        review=client.post('/api/crm/schools/merge/preview',headers=headers,json=body)
        assert review.status_code==200,review.get_json()
        payload={**body,'review_token':review.get_json()['review_token']}
        # Competing commits must produce one merge, with no duplicate history.
        from concurrent.futures import ThreadPoolExecutor
        def commit_once(_):
            with svc.app.test_client() as worker_client:
                return worker_client.post('/api/crm/schools/merge/commit',headers=headers,json=payload).status_code
        svc.db.session.remove()
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(commit_once,range(2)))
        assert sorted(results)==[200,404],results
        assert svc.SalesTask.query.filter_by(school_id=second_id,priority='low').count()==1
        assert svc.SchoolContact.query.filter_by(school_id=second_id).count()==1
        assert client.get('/api/outreach/reporting',headers=headers).status_code==200
        print('Postgres checklist passed: migration twice, RLS/public grants, competing reviewed merges, contact dedupe, Low-priority task history and reporting.')
        print('Postgres passed: migration twice, existing school unchanged, RLS retained, constraints and separate workspace queries.')


if __name__ == '__main__':
    main()
