-- Two automatic follow-ups (day 3 and day 7): count how many each sent email has had.
-- Apply BEFORE deploying the backend that reads followup_count. Additive and safe to run again.
BEGIN;

ALTER TABLE sent_emails
    ADD COLUMN IF NOT EXISTS followup_count integer NOT NULL DEFAULT 0;

-- Rows from before this change only set followup_sent; that means one follow-up went out.
UPDATE sent_emails SET followup_count = 1
WHERE followup_sent IS TRUE AND followup_count = 0;

COMMIT;
