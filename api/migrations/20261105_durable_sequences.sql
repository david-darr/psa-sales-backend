-- After 20261105_contact_outreach.sql. No enrollment or automatic authorization is created.
BEGIN;
ALTER TABLE sent_emails ADD COLUMN IF NOT EXISTS sequence_managed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS lease_owner VARCHAR(36);
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS lease_until TIMESTAMP;
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS available_at TIMESTAMP;
CREATE TABLE IF NOT EXISTS mail_sequences (
 id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
 definition TEXT NOT NULL, archived BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS mail_sequence_versions (
 id SERIAL PRIMARY KEY, sequence_id INTEGER NOT NULL REFERENCES mail_sequences(id), revision INTEGER NOT NULL,
 definition TEXT NOT NULL, actor_id INTEGER NOT NULL REFERENCES users(id), created_at TIMESTAMP NOT NULL,
 UNIQUE(sequence_id,revision)
);
CREATE TABLE IF NOT EXISTS mail_sequence_enrollments (
 id SERIAL PRIMARY KEY, original_id INTEGER REFERENCES sent_emails(id) ON DELETE SET NULL,
 user_id INTEGER NOT NULL REFERENCES users(id), school_id INTEGER REFERENCES sales_schools(id) ON DELETE SET NULL,
 contact_id INTEGER NOT NULL REFERENCES contacts(id), sequence_id INTEGER NOT NULL REFERENCES mail_sequences(id),
 revision INTEGER NOT NULL, generation INTEGER NOT NULL DEFAULT 1, campaign_id VARCHAR(36) NOT NULL,
 mode VARCHAR(12) NOT NULL DEFAULT 'review', status VARCHAR(12) NOT NULL DEFAULT 'active', reason TEXT,
 snapshot TEXT NOT NULL, starts_at TIMESTAMP NOT NULL, ends_at TIMESTAMP NOT NULL, approved_at TIMESTAMP NOT NULL,
 UNIQUE(original_id,generation)
);
CREATE TABLE IF NOT EXISTS mail_sequence_steps (
 id SERIAL PRIMARY KEY, enrollment_id INTEGER NOT NULL REFERENCES mail_sequence_enrollments(id), number INTEGER NOT NULL,
 due_at TIMESTAMP NOT NULL, status VARCHAR(12) NOT NULL DEFAULT 'waiting', content TEXT NOT NULL,
 recipient_id INTEGER UNIQUE REFERENCES outreach_recipients(id), approved_until TIMESTAMP,
 lease_token VARCHAR(36), lease_until TIMESTAMP, sent_at TIMESTAMP, UNIQUE(enrollment_id,number)
);
CREATE TABLE IF NOT EXISTS mail_sequence_reviews (
 id VARCHAR(36) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), payload TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, result TEXT
);
CREATE TABLE IF NOT EXISTS outreach_worker_heartbeats (
 id VARCHAR(36) PRIMARY KEY, last_seen_at TIMESTAMP NOT NULL, status VARCHAR(12) NOT NULL,
 last_error TEXT, batches INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_sequence_steps_due ON mail_sequence_steps(status,due_at);
CREATE INDEX IF NOT EXISTS ix_outreach_durable_queue ON outreach_batches(status,heartbeat_at);
ALTER TABLE mail_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_sequence_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_sequence_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_sequence_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_sequence_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_worker_heartbeats ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE mail_sequences,mail_sequence_versions,mail_sequence_enrollments,mail_sequence_steps,mail_sequence_reviews,outreach_worker_heartbeats FROM anon,authenticated;
REVOKE ALL ON SEQUENCE mail_sequences_id_seq,mail_sequence_versions_id_seq,mail_sequence_enrollments_id_seq,mail_sequence_steps_id_seq FROM anon,authenticated;
COMMIT;
