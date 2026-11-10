-- After contacts/templates. Does not reassign existing schools or invite anyone.
BEGIN;
ALTER TABLE sales_schools ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE sales_schools ADD COLUMN IF NOT EXISTS ownership_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE outreach_recipients ADD COLUMN IF NOT EXISTS ownership_version INTEGER;
-- Existing rows are bound to the initial owner epoch; deleted schools remain protected by worker checks.
UPDATE outreach_recipients r SET ownership_version=s.ownership_version
FROM sales_schools s WHERE r.school_id=s.id AND r.ownership_version IS NULL;
CREATE INDEX IF NOT EXISTS ix_sales_schools_unassigned ON sales_schools(id) WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS ix_sales_schools_county ON sales_schools(lower(trim(county)));
CREATE TABLE IF NOT EXISTS school_assignment_reviews (
 id VARCHAR(36) PRIMARY KEY, actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 target_id INTEGER REFERENCES users(id) ON DELETE SET NULL, selection TEXT NOT NULL,
 snapshot TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, result TEXT
);
ALTER TABLE school_assignment_reviews ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE school_assignment_reviews FROM anon, authenticated;
COMMIT;
