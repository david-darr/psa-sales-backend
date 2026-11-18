BEGIN;
CREATE TABLE IF NOT EXISTS taskbar_pending_assignments (
 taskbar_task_id varchar(36) PRIMARY KEY, payload text NOT NULL,
 assignee_email varchar(320), reason varchar(300) NOT NULL, updated_at timestamp NOT NULL
);
ALTER TABLE taskbar_pending_assignments ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON taskbar_pending_assignments FROM anon, authenticated;
ALTER TABLE outreach_batches ADD COLUMN IF NOT EXISTS audience varchar(50);
ALTER TABLE sales_tasks DROP CONSTRAINT IF EXISTS sales_tasks_priority_check;
ALTER TABLE sales_tasks ADD CONSTRAINT sales_tasks_priority_check CHECK (priority IN ('low','normal','high'));
UPDATE sales_tasks t SET priority='low',version=version+1 FROM sales_task_links l WHERE l.sales_task_id=t.id AND l.taskbar_priority='Low' AND t.priority='normal';
COMMIT;
