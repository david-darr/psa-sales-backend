-- Seasonal program accounting from Christopher's 2026-10-28 commission rules.
-- No conversion of legacy deal values: they do not identify seasons or expenses.
BEGIN;
CREATE TABLE IF NOT EXISTS program_commissions (
    id serial PRIMARY KEY,
    sales_school_id integer REFERENCES sales_schools(id) ON DELETE SET NULL,
    school_name varchar(250) NOT NULL,
    season varchar(80) NOT NULL,
    program varchar(120) NOT NULL,
    record_key varchar(240) NOT NULL,
    rep_id integer REFERENCES users(id) ON DELETE SET NULL,
    rep_name varchar(250) NOT NULL,
    sale_type varchar(10) NOT NULL CHECK (sale_type IN ('new', 'renewal')),
    gross numeric(12,2) NOT NULL CHECK (gross >= 0),
    leagueapps boolean NOT NULL,
    cash_expenses numeric(12,2) NOT NULL CHECK (cash_expenses >= 0),
    rep_payout numeric(12,2) CHECK (rep_payout IS NULL OR rep_payout >= 0),
    notes text NOT NULL DEFAULT '',
    voided boolean NOT NULL DEFAULT false,
    revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamp without time zone NOT NULL,
    CONSTRAINT uq_program_commission UNIQUE (sales_school_id, record_key),
    CONSTRAINT program_expenses_within_net CHECK (
        cash_expenses <= gross - CASE WHEN leagueapps THEN round(gross * 0.035, 2) ELSE 0 END),
    CONSTRAINT program_payout_within_pool CHECK (rep_payout IS NULL OR rep_payout <= round(
        (gross - CASE WHEN leagueapps THEN round(gross * 0.035, 2) ELSE 0 END - cash_expenses)
        * CASE WHEN sale_type = 'new' THEN 0.15 ELSE 0.075 END, 2))
);
CREATE INDEX IF NOT EXISTS ix_program_commissions_season_rep ON program_commissions(season, rep_id);
CREATE TABLE IF NOT EXISTS program_commission_events (
    id serial PRIMARY KEY,
    program_commission_id integer NOT NULL REFERENCES program_commissions(id),
    actor_id integer REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp without time zone NOT NULL,
    before_json text,
    after_json text NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_program_commission_events_record ON program_commission_events(program_commission_id);
ALTER TABLE program_commissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE program_commission_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE program_commissions, program_commission_events FROM anon, authenticated;
REVOKE ALL ON SEQUENCE program_commissions_id_seq, program_commission_events_id_seq FROM anon, authenticated;
COMMIT;
