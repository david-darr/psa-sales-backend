-- Apply in Supabase SQL Editor before deploying the matching backend commit.
-- Additive and safe to run again. Existing sent emails are linked only when
-- exactly one employee school has the same owner, name, and recipient address.
BEGIN;

ALTER TABLE sales_schools
    ADD COLUMN IF NOT EXISTS next_action text,
    ADD COLUMN IF NOT EXISTS next_action_at timestamp without time zone;

ALTER TABLE sent_emails
    ADD COLUMN IF NOT EXISTS sales_school_id integer REFERENCES sales_schools(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS sent_messages (
    id serial PRIMARY KEY,
    sent_email_id integer NOT NULL REFERENCES sent_emails(id),
    message_id text NOT NULL UNIQUE,
    subject text NOT NULL,
    kind text NOT NULL,
    sent_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);
CREATE INDEX IF NOT EXISTS ix_sent_messages_sent_email_id ON sent_messages(sent_email_id);
ALTER TABLE sent_messages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE sent_messages FROM anon, authenticated;
REVOKE ALL ON SEQUENCE sent_messages_id_seq FROM anon, authenticated;

CREATE TABLE IF NOT EXISTS mail_sync_states (
    user_id integer PRIMARY KEY REFERENCES users(id),
    uidvalidity text,
    last_uid bigint NOT NULL DEFAULT 0,
    pending_count integer NOT NULL DEFAULT 0,
    last_checked_at timestamp without time zone,
    last_success_at timestamp without time zone,
    last_error text
);
INSERT INTO mail_sync_states(user_id)
SELECT id FROM users WHERE email_password IS NOT NULL
ON CONFLICT (user_id) DO NOTHING;
ALTER TABLE mail_sync_states ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE mail_sync_states FROM anon, authenticated;

CREATE TABLE IF NOT EXISTS school_activities (
    id serial PRIMARY KEY,
    sales_school_id integer NOT NULL REFERENCES sales_schools(id) ON DELETE CASCADE,
    actor_id integer NOT NULL REFERENCES users(id),
    kind text NOT NULL,
    detail text NOT NULL,
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);
CREATE INDEX IF NOT EXISTS ix_school_activities_school_time
    ON school_activities(sales_school_id, created_at DESC);
ALTER TABLE school_activities ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE school_activities FROM anon, authenticated;
REVOKE ALL ON SEQUENCE school_activities_id_seq FROM anon, authenticated;

CREATE INDEX IF NOT EXISTS ix_sent_emails_sales_school_id
    ON sent_emails(sales_school_id);

WITH unique_matches AS (
    SELECT email.id AS sent_email_id, MIN(school.id) AS school_id
    FROM sent_emails AS email
    JOIN sales_schools AS school
      ON school.user_id = email.user_id
     AND lower(trim(school.school_name)) = lower(trim(email.school_name))
     AND (
       lower(trim(school.email)) = lower(trim(email.school_email))
       OR position('"' || lower(trim(email.school_email)) || '"'
           in lower(coalesce(school.additional_emails, ''))) > 0
     )
    WHERE email.sales_school_id IS NULL
    GROUP BY email.id
    HAVING COUNT(*) = 1
)
UPDATE sent_emails AS email
SET sales_school_id = matches.school_id
FROM unique_matches AS matches
WHERE email.id = matches.sent_email_id;

COMMIT;
