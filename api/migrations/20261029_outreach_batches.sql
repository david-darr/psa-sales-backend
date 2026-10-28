-- Apply AFTER 20261028_sales_workspace.sql. Additive and safe to run again.
-- Durable outreach batches: one row per send job, one row per recipient.
BEGIN;

CREATE TABLE IF NOT EXISTS outreach_batches (
    id serial PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(id),
    kind varchar(12) NOT NULL,
    status varchar(12) NOT NULL DEFAULT 'queued',
    subject text,
    attachments boolean NOT NULL DEFAULT false,
    worker_token varchar(36),
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    started_at timestamp without time zone,
    finished_at timestamp without time zone,
    heartbeat_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS outreach_recipients (
    id serial PRIMARY KEY,
    batch_id integer NOT NULL REFERENCES outreach_batches(id) ON DELETE CASCADE,
    position integer NOT NULL DEFAULT 0,
    school_id integer REFERENCES sales_schools(id) ON DELETE SET NULL,
    school_name text NOT NULL,
    email text NOT NULL DEFAULT '',
    status varchar(12) NOT NULL DEFAULT 'queued',
    error text,
    attempts integer NOT NULL DEFAULT 0,
    sent_email_id integer REFERENCES sent_emails(id) ON DELETE SET NULL,
    sent_at timestamp without time zone,
    subject text,
    body text,
    attachments text,
    followup_of_email_id integer REFERENCES sent_emails(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_outreach_batches_user_created ON outreach_batches(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_outreach_recipients_batch ON outreach_recipients(batch_id, position);
CREATE INDEX IF NOT EXISTS ix_outreach_recipients_school ON outreach_recipients(school_id);

ALTER TABLE outreach_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_recipients ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE outreach_batches, outreach_recipients FROM anon, authenticated;
REVOKE ALL ON SEQUENCE outreach_batches_id_seq, outreach_recipients_id_seq FROM anon, authenticated;

COMMIT;
