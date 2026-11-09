-- Apply after 20261105_contacts.sql. No seed and no sending schedule changes.
BEGIN;
CREATE TABLE IF NOT EXISTS mail_template_assets (
 id VARCHAR(64) PRIMARY KEY, name VARCHAR(180) NOT NULL, payload BYTEA NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS mail_templates (
 id SERIAL PRIMARY KEY, source_key VARCHAR(120) UNIQUE, revision INTEGER NOT NULL DEFAULT 1,
 archived BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS mail_template_versions (
 id SERIAL PRIMARY KEY, template_id INTEGER NOT NULL REFERENCES mail_templates(id), revision INTEGER NOT NULL,
 snapshot TEXT NOT NULL, actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(template_id, revision)
);
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS template_snapshot TEXT;
ALTER TABLE mail_template_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_template_versions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE mail_template_assets, mail_templates, mail_template_versions FROM anon, authenticated;
REVOKE ALL ON SEQUENCE mail_templates_id_seq, mail_template_versions_id_seq FROM anon, authenticated;
CREATE TABLE IF NOT EXISTS mail_template_imports (
 id VARCHAR(36) PRIMARY KEY, actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 payload TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, result TEXT
);
ALTER TABLE mail_template_imports ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE mail_template_imports FROM anon, authenticated;
COMMIT;
