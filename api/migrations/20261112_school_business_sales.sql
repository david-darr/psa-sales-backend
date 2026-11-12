-- Apply before releasing School Sales / Business Sales. No records move areas.
BEGIN;
DO $migration$
DECLARE item text;
BEGIN
  FOREACH item IN ARRAY ARRAY['sales_schools','sales_tasks','sent_emails','outreach_batches','outreach_campaigns','outreach_contact_reviews','mail_templates','mail_template_imports','mail_sequences','mail_sequence_enrollments','mail_sequence_reviews','approved_campaign_plans','agent_outreach_drafts','contact_imports','school_assignment_reviews'] LOOP
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS sales_workspace varchar(8) NOT NULL DEFAULT ''school''', item);
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = item || '_sales_workspace_check' AND conrelid = to_regclass(item)) THEN
      EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (sales_workspace IN (''school'', ''business''))', item, item || '_sales_workspace_check');
    END IF;
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (sales_workspace)', 'ix_' || item || '_sales_workspace', item);
  END LOOP;
END $migration$;
ALTER TABLE sales_schools ADD COLUMN IF NOT EXISTS industry varchar(100), ADD COLUMN IF NOT EXISTS sponsorship_value numeric(12,2);
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='sales_schools_sponsorship_value_check' AND conrelid='sales_schools'::regclass) THEN
    ALTER TABLE sales_schools ADD CONSTRAINT sales_schools_sponsorship_value_check CHECK (sponsorship_value IS NULL OR (sales_workspace='business' AND sponsorship_value>=0));
  END IF;
END $migration$;
-- No grants or RLS policies change; existing private access stays in force.
COMMIT;
