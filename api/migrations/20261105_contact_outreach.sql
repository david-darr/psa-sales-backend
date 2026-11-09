-- Apply after contacts, shared templates and school ownership. Does not send
-- mail or enroll recipients. Existing rows remain historical school sends.
BEGIN;
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS campaign_id VARCHAR(36);
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS paused_reason TEXT;
ALTER TABLE outreach_recipients ADD COLUMN IF NOT EXISTS contact_id INTEGER REFERENCES contacts(id);
ALTER TABLE outreach_recipients ADD COLUMN IF NOT EXISTS contact_link_id INTEGER REFERENCES school_contacts(id) ON DELETE SET NULL;
ALTER TABLE outreach_recipients ADD COLUMN IF NOT EXISTS contact_version INTEGER;
ALTER TABLE outreach_recipients ADD COLUMN IF NOT EXISTS link_version INTEGER;
ALTER TABLE outreach_recipients ADD COLUMN IF NOT EXISTS attempted_at TIMESTAMP;
CREATE TABLE IF NOT EXISTS outreach_campaigns (
 id VARCHAR(36) PRIMARY KEY, name VARCHAR(150) NOT NULL, reason TEXT NOT NULL,
 daily_limit INTEGER NOT NULL DEFAULT 150 CHECK(daily_limit > 0), archived BOOLEAN NOT NULL DEFAULT FALSE,
 created_by INTEGER REFERENCES users(id), created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS outreach_contact_reviews (
 id VARCHAR(36) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 snapshot TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, batch_id INTEGER REFERENCES outreach_batches(id)
);
CREATE TABLE IF NOT EXISTS outreach_contact_ledger (
 id SERIAL PRIMARY KEY, campaign_id VARCHAR(36) NOT NULL, contact_id INTEGER NOT NULL REFERENCES contacts(id),
 step VARCHAR(40) NOT NULL, recipient_id INTEGER NOT NULL UNIQUE REFERENCES outreach_recipients(id),
 CONSTRAINT uq_campaign_contact_step UNIQUE(campaign_id, contact_id, step)
);
CREATE TABLE IF NOT EXISTS mail_contact_signals (
 id SERIAL PRIMARY KEY, contact_id INTEGER NOT NULL REFERENCES contacts(id), kind VARCHAR(20) NOT NULL,
 source VARCHAR(100) NOT NULL UNIQUE, detail TEXT NOT NULL, actor_id INTEGER REFERENCES users(id), created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS outreach_send_attempts (
 id SERIAL PRIMARY KEY, recipient_id INTEGER NOT NULL REFERENCES outreach_recipients(id),
 attempt_number INTEGER NOT NULL, started_at TIMESTAMP NOT NULL, status VARCHAR(12) NOT NULL,
 CONSTRAINT uq_recipient_attempt UNIQUE(recipient_id,attempt_number)
);
CREATE INDEX IF NOT EXISTS ix_outreach_contact_active ON outreach_recipients(lower(email),status);
CREATE INDEX IF NOT EXISTS ix_sent_emails_contact_mailbox ON sent_emails(lower(trim(school_email)));
ALTER TABLE outreach_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_contact_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_contact_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_contact_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_send_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE outreach_campaigns, outreach_contact_reviews, outreach_contact_ledger, mail_contact_signals, outreach_send_attempts FROM anon, authenticated;
REVOKE ALL ON SEQUENCE outreach_contact_ledger_id_seq, mail_contact_signals_id_seq, outreach_send_attempts_id_seq FROM anon, authenticated;
COMMIT;
