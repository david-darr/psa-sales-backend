-- Taskbar two-way task sync (api/taskbar_sync.py). Apply AFTER 20261028_sales_workspace.sql.
-- Additive only: no existing table changes. Safe to apply before the code ships; the
-- backend ignores these tables until TASKBAR_SYNC_ENABLED=true.
BEGIN;
CREATE TABLE IF NOT EXISTS sales_task_links (
    sales_task_id integer PRIMARY KEY REFERENCES sales_tasks(id) ON DELETE CASCADE,
    taskbar_task_id varchar(36) UNIQUE,
    taskbar_revision bigint,
    taskbar_status varchar(20),
    taskbar_priority varchar(10),
    taskbar_updated_at timestamp without time zone,
    psa_version integer NOT NULL DEFAULT 0,
    dirty_at timestamp without time zone,
    due_defaulted boolean NOT NULL DEFAULT false,
    origin varchar(10) NOT NULL DEFAULT 'psa' CHECK (origin IN ('psa', 'taskbar')),
    state varchar(12) NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'synced', 'error', 'detached')),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamp without time zone,
    last_error varchar(300),
    last_synced_at timestamp without time zone
);
CREATE INDEX IF NOT EXISTS ix_sales_task_links_retry ON sales_task_links(state, next_attempt_at);
CREATE TABLE IF NOT EXISTS taskbar_user_links (
    user_id integer PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    taskbar_user_id varchar(36) NOT NULL UNIQUE,
    matched_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);
ALTER TABLE sales_task_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE taskbar_user_links ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE sales_task_links, taskbar_user_links FROM anon, authenticated;
COMMIT;
