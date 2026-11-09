-- Additive campaign approvals. Does not enable the worker or grant API scopes.
BEGIN;
CREATE TABLE IF NOT EXISTS approved_campaign_plans (
 id VARCHAR(36) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), key_id INTEGER NOT NULL REFERENCES agent_api_keys(id),
 revision INTEGER NOT NULL DEFAULT 1, dispatch_round INTEGER NOT NULL DEFAULT 0, status VARCHAR(20) NOT NULL DEFAULT 'awaiting', settings TEXT NOT NULL, snapshot TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, review_until TIMESTAMP NOT NULL, approved_at TIMESTAMP, approval_id VARCHAR(36), reason TEXT
);
CREATE INDEX IF NOT EXISTS ix_approved_campaign_plans_user_id ON approved_campaign_plans(user_id);
CREATE TABLE IF NOT EXISTS approved_campaign_members (
 id SERIAL PRIMARY KEY, plan_id VARCHAR(36) NOT NULL REFERENCES approved_campaign_plans(id), contact_id INTEGER NOT NULL REFERENCES contacts(id), school_id INTEGER REFERENCES sales_schools(id) ON DELETE SET NULL,
 snapshot TEXT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'waiting', reason TEXT,
 recipient_id INTEGER UNIQUE REFERENCES outreach_recipients(id), enrollment_id INTEGER UNIQUE REFERENCES mail_sequence_enrollments(id),
 UNIQUE(plan_id,contact_id)
);
CREATE INDEX IF NOT EXISTS ix_approved_campaign_members_school_id ON approved_campaign_members(school_id);
CREATE INDEX IF NOT EXISTS ix_approved_campaign_members_plan_id ON approved_campaign_members(plan_id);
CREATE TABLE IF NOT EXISTS approved_campaign_events (
 id SERIAL PRIMARY KEY, plan_id VARCHAR(36) NOT NULL REFERENCES approved_campaign_plans(id), event VARCHAR(40) NOT NULL, revision INTEGER NOT NULL, created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_approved_campaign_events_plan_id ON approved_campaign_events(plan_id);
CREATE TABLE IF NOT EXISTS approved_campaign_summaries (
 id SERIAL PRIMARY KEY, plan_id VARCHAR(36) NOT NULL REFERENCES approved_campaign_plans(id), day VARCHAR(10) NOT NULL, payload TEXT NOT NULL, UNIQUE(plan_id,day)
);
ALTER TABLE approved_campaign_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE approved_campaign_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE approved_campaign_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE approved_campaign_summaries ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE approved_campaign_plans,approved_campaign_members,approved_campaign_events,approved_campaign_summaries FROM anon,authenticated;
REVOKE ALL ON SEQUENCE approved_campaign_members_id_seq,approved_campaign_events_id_seq,approved_campaign_summaries_id_seq FROM anon,authenticated;
COMMIT;
