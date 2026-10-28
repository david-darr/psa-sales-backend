-- ONE-TIME LAUNCH RESET. Destructive. Run only with explicit approval, after a backup.
-- Apply AFTER 20261029_launch_admin.sql (it clears the tables that migration adds).
--
-- Keeps: administrator accounts (users.admin = true) and their logins and mail settings,
--        the geocoder cache (geocoded_addresses), and the unused legacy tables
--        ("PSA Schools", "Happy Feet Schools", "Employees").
-- Deletes: every school (rep-owned and the shared directory), email, reply, thread,
--          task, activity, outreach batch, map snapshot, invitation, join link,
--          commission split, mailbox sync cursor, and every non-admin account.
--
-- Preview first (read-only):
--   SELECT count(*) FILTER (WHERE admin) AS kept_admins,
--          count(*) FILTER (WHERE NOT admin) AS deleted_users FROM users;
BEGIN;

DO $$
DECLARE
    -- sales_task_links comes from a later migration; include it only when present,
    -- because TRUNCATE must list every table that references sales_tasks.
    tables text := 'email_replies, sent_messages, outreach_recipients, outreach_batches, '
        || 'sent_emails, school_activities, sales_tasks, commission_splits, sales_schools, '
        || 'schools, map_snapshots, mail_sync_states, employee_invitations, join_links';
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE admin) THEN
        RAISE EXCEPTION 'No administrator account exists; refusing to reset';
    END IF;
    IF to_regclass('public.sales_task_links') IS NOT NULL THEN
        tables := tables || ', sales_task_links';
    END IF;
    EXECUTE 'TRUNCATE TABLE ' || tables || ' RESTART IDENTITY';
END $$;

DELETE FROM users WHERE NOT admin;
UPDATE users SET commission_rate = NULL;

-- Expect: only administrators remain and every data table is empty.
SELECT
    (SELECT count(*) FROM users) AS users_left,
    (SELECT count(*) FROM users WHERE NOT admin) AS non_admins_left,
    (SELECT count(*) FROM sales_schools) AS sales_schools,
    (SELECT count(*) FROM sent_emails) AS sent_emails,
    (SELECT count(*) FROM sales_tasks) AS tasks;

COMMIT;
