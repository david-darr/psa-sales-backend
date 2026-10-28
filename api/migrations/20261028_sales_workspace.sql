-- Apply AFTER 20261005_reply_sync_school_workspace.sql, before this release.
BEGIN;
CREATE TABLE IF NOT EXISTS geocoded_addresses (
    address_key text PRIMARY KEY, lat double precision, lng double precision,
    checked_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);
CREATE TABLE IF NOT EXISTS map_snapshots (
    id integer PRIMARY KEY, data_json text NOT NULL DEFAULT '{}',
    updated_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);
ALTER TABLE geocoded_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE map_snapshots ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE geocoded_addresses, map_snapshots FROM anon, authenticated;
CREATE TABLE IF NOT EXISTS sales_tasks (
    id serial PRIMARY KEY,
    title varchar(240) NOT NULL,
    user_id integer NOT NULL REFERENCES users(id),
    school_id integer REFERENCES sales_schools(id) ON DELETE SET NULL,
    due_at timestamp without time zone,
    priority varchar(10) NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal', 'high')),
    status varchar(12) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed')),
    version integer NOT NULL DEFAULT 1,
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
    completed_at timestamp without time zone
);
ALTER TABLE sales_tasks ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE sales_tasks FROM anon, authenticated;
REVOKE ALL ON SEQUENCE sales_tasks_id_seq FROM anon, authenticated;
CREATE INDEX IF NOT EXISTS ix_sales_tasks_owner_due ON sales_tasks(user_id, status, due_at, id);
CREATE INDEX IF NOT EXISTS ix_sales_tasks_school ON sales_tasks(school_id);
CREATE INDEX IF NOT EXISTS ix_sales_schools_owner_stage ON sales_schools(user_id, status, id);
CREATE INDEX IF NOT EXISTS ix_sales_schools_next_action ON sales_schools(user_id, next_action_at);
CREATE INDEX IF NOT EXISTS ix_sent_emails_owner_time ON sent_emails(user_id, sent_at);
COMMIT;
