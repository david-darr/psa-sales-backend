-- Apply AFTER 20261029_accounts_portfolio.sql. Additive and safe to run again.
--   * commissions: a default rate per rep, a deal value per closed school, and
--     optional per-school splits that override the closer's 100% default
--   * join_links: reusable, expiring, revocable sign-up links for new reps
BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS commission_rate numeric(5,2);
ALTER TABLE sales_schools
    ADD COLUMN IF NOT EXISTS deal_value numeric(12,2);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_commission_rate_check') THEN
        ALTER TABLE users ADD CONSTRAINT users_commission_rate_check
            CHECK (commission_rate IS NULL OR (commission_rate >= 0 AND commission_rate <= 100));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_schools_deal_value_check') THEN
        ALTER TABLE sales_schools ADD CONSTRAINT sales_schools_deal_value_check
            CHECK (deal_value IS NULL OR deal_value >= 0);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS commission_splits (
    id serial PRIMARY KEY,
    sales_school_id integer NOT NULL REFERENCES sales_schools(id) ON DELETE CASCADE,
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_pct numeric(5,2) NOT NULL CHECK (share_pct > 0 AND share_pct <= 100),
    rate_pct numeric(5,2) CHECK (rate_pct IS NULL OR (rate_pct >= 0 AND rate_pct <= 100)),
    CONSTRAINT uq_commission_split UNIQUE (sales_school_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_commission_splits_user ON commission_splits(user_id);

CREATE TABLE IF NOT EXISTS join_links (
    id serial PRIMARY KEY,
    token_hash varchar(64) NOT NULL UNIQUE,
    label text,
    created_by integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    expires_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    max_uses integer CHECK (max_uses IS NULL OR max_uses > 0),
    use_count integer NOT NULL DEFAULT 0
);

ALTER TABLE commission_splits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE commission_splits FROM anon, authenticated;
REVOKE ALL ON SEQUENCE commission_splits_id_seq FROM anon, authenticated;
ALTER TABLE join_links ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE join_links FROM anon, authenticated;
REVOKE ALL ON SEQUENCE join_links_id_seq FROM anon, authenticated;

COMMIT;
