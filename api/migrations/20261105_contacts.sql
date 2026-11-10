-- Additive contact foundation. Apply before this version of the backend.
-- PostgreSQL 16+ (Supabase uses 17): pg_input_is_valid protects legacy JSON.
BEGIN;
ALTER TABLE sales_schools ADD COLUMN IF NOT EXISTS county varchar(80);
CREATE TABLE IF NOT EXISTS contacts (
    id serial PRIMARY KEY,
    email varchar(254) NOT NULL UNIQUE CHECK (email = lower(btrim(email))),
    do_not_contact boolean NOT NULL DEFAULT false,
    suppression_reason text NOT NULL DEFAULT '',
    version integer NOT NULL DEFAULT 1 CHECK (version > 0)
);
CREATE TABLE IF NOT EXISTS school_contacts (
    id serial PRIMARY KEY,
    school_id integer NOT NULL REFERENCES sales_schools(id) ON DELETE CASCADE,
    contact_id integer NOT NULL REFERENCES contacts(id),
    name varchar(150) NOT NULL DEFAULT '',
    roles_json text NOT NULL DEFAULT '["unknown"]',
    tags_json text NOT NULL DEFAULT '[]',
    is_primary boolean NOT NULL DEFAULT false,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    CONSTRAINT uq_school_contact UNIQUE (school_id, contact_id)
);
CREATE INDEX IF NOT EXISTS ix_school_contacts_contact_id ON school_contacts(contact_id);
CREATE TABLE IF NOT EXISTS contact_events (
    id serial PRIMARY KEY,
    contact_id integer NOT NULL REFERENCES contacts(id),
    school_id integer REFERENCES sales_schools(id) ON DELETE SET NULL,
    actor_id integer REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp without time zone NOT NULL,
    detail text NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_contact_events_contact ON contact_events(contact_id);
CREATE TABLE IF NOT EXISTS contact_imports (
    id varchar(64) PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_hash varchar(64) NOT NULL,
    rows_json text NOT NULL,
    plan_json text NOT NULL,
    snapshot varchar(64) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    result_json text
);
CREATE INDEX IF NOT EXISTS ix_contact_imports_user_expiry ON contact_imports(user_id, expires_at);
CREATE TABLE IF NOT EXISTS contact_import_guard (id integer PRIMARY KEY, revision integer NOT NULL);
INSERT INTO contact_import_guard VALUES (1, 0) ON CONFLICT DO NOTHING;

-- Keep all original fields. Do not infer a role, stage, owner, or county.
CREATE TEMP TABLE contact_backfill ON COMMIT DROP AS
WITH legacy AS (
    SELECT id AS school_id, email, true AS is_primary, left(coalesce(contact_name, ''),150) AS name FROM sales_schools
    UNION ALL
    SELECT s.id, a.value, false, '' FROM sales_schools s
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN pg_input_is_valid(coalesce(s.additional_emails,''), 'jsonb') THEN
            CASE WHEN jsonb_typeof(s.additional_emails::jsonb)='array' THEN s.additional_emails::jsonb ELSE '[]'::jsonb END
        ELSE '[]'::jsonb END) AS a(value)
)
SELECT school_id, lower(btrim(email)) AS email, bool_or(is_primary) AS is_primary,
       max(name) AS name
FROM legacy WHERE length(email) <= 254 AND btrim(email) ~ '^[^@[:space:],;]+@[^@[:space:],;]+\.[^@[:space:],;]+$'
GROUP BY school_id, lower(btrim(email));
INSERT INTO contacts (email) SELECT DISTINCT email FROM contact_backfill ON CONFLICT DO NOTHING;
INSERT INTO school_contacts (school_id, contact_id, name, is_primary)
SELECT b.school_id,c.id,b.name,b.is_primary FROM contact_backfill b JOIN contacts c ON c.email=b.email
ON CONFLICT (school_id, contact_id) DO NOTHING;
-- Prior school-level opt-outs remain in place; carry them into mailbox safety too.
UPDATE contacts c SET do_not_contact=true, suppression_reason='Existing school-level suppression', version=version+1
WHERE NOT c.do_not_contact AND EXISTS (
    SELECT 1 FROM school_contacts l JOIN school_activities a ON a.sales_school_id=l.school_id
    WHERE l.contact_id=c.id AND a.kind IN ('unsubscribed','do_not_contact'));

ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE school_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_imports ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_import_guard ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE contacts,school_contacts,contact_events,contact_imports,contact_import_guard FROM anon,authenticated;
REVOKE ALL ON SEQUENCE contacts_id_seq,school_contacts_id_seq,contact_events_id_seq FROM anon,authenticated;
COMMIT;
