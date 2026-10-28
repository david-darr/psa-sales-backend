-- In-app support and error reports (api/support.py). Additive and safe to run again.
BEGIN;

CREATE TABLE IF NOT EXISTS support_reports (
    id serial PRIMARY KEY,
    user_id integer REFERENCES users(id) ON DELETE SET NULL,
    kind varchar(12) NOT NULL,
    subject varchar(160) NOT NULL,
    message text NOT NULL,
    page varchar(300),
    error text,
    browser varchar(300),
    delivered boolean NOT NULL DEFAULT false,
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS ix_support_reports_user_time ON support_reports(user_id, created_at);

ALTER TABLE support_reports ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE support_reports FROM anon, authenticated;
REVOKE ALL ON SEQUENCE support_reports_id_seq FROM anon, authenticated;

COMMIT;
