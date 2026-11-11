-- After contacts/templates/ownership/contact-outreach/durable-sequences drafts.
-- Existing keys receive no new permissions. Creates no key or approval.
BEGIN;
ALTER TABLE agent_api_keys ALTER COLUMN scopes TYPE VARCHAR(255);
ALTER TABLE agent_api_keys DROP CONSTRAINT IF EXISTS agent_api_keys_scopes_check;
ALTER TABLE agent_api_keys ADD CONSTRAINT agent_api_keys_scopes_check CHECK (
 scopes ~ '^read(,write)?(,(schools:import|outreach:read|outreach:prepare|outreach:send|library:manage|commissions:manage|team:manage))*$'
);
CREATE TABLE IF NOT EXISTS agent_outreach_drafts (
 id VARCHAR(36) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 key_id INTEGER NOT NULL REFERENCES agent_api_keys(id), settings TEXT NOT NULL,
 preview TEXT NOT NULL, review_token VARCHAR(100) NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
 status VARCHAR(16) NOT NULL DEFAULT 'awaiting', created_at TIMESTAMP NOT NULL,
 expires_at TIMESTAMP NOT NULL, approval_id VARCHAR(36), approved_by INTEGER REFERENCES users(id),
 approved_at TIMESTAMP, batch_id INTEGER UNIQUE REFERENCES outreach_batches(id), executed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_agent_outreach_drafts_user_id ON agent_outreach_drafts(user_id);
CREATE INDEX IF NOT EXISTS ix_agent_outreach_drafts_key_id ON agent_outreach_drafts(key_id);
CREATE TABLE IF NOT EXISTS agent_outreach_events (
 id SERIAL PRIMARY KEY, draft_id VARCHAR(36) NOT NULL REFERENCES agent_outreach_drafts(id),
 key_id INTEGER NOT NULL REFERENCES agent_api_keys(id), user_id INTEGER NOT NULL REFERENCES users(id),
 event VARCHAR(24) NOT NULL, approval_id VARCHAR(36), batch_id INTEGER REFERENCES outreach_batches(id),
 created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_outreach_events_draft_id ON agent_outreach_events(draft_id);
ALTER TABLE agent_outreach_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_outreach_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE agent_outreach_drafts,agent_outreach_events FROM anon,authenticated;
REVOKE ALL ON SEQUENCE agent_outreach_events_id_seq FROM anon,authenticated;
COMMIT;
