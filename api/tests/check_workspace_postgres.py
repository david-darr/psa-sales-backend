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
        print('Postgres passed: migration twice, existing school unchanged, RLS retained, constraints and separate workspace queries.')


if __name__ == '__main__':
    main()
