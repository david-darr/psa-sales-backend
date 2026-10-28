# PSA Sales and Taskbar task sync

Two-way sync of sales tasks between PSA Sales and the Taskbar **Sales** program. Changes show up on the other side in a few seconds, and within 1 minute at worst. Nothing here is live until David applies the steps below. Everything ships switched off.

## What was built

| Repo | Branch | Files |
| --- | --- | --- |
| PSA backend (`psa-due-followups`) | `feature/taskbar-sync` (worktree `..\psa-taskbar-sync`, from `feature/psa-sales-platform`) | `api/taskbar_sync.py` (new), `api/migrations/20261030_taskbar_sync.sql` (new), `api/tests/test_taskbar_sync.py` (new), this doc, a 3-line hook at the end of `api/api.py` |
| PSA frontend | `feature/taskbar-sync-refresh` (worktree `..\psa-frontend-taskbar-sync`, from `design/psa-sales-platform`) | `src/lib/crm.js` (`useAutoRefresh`), `src/Tasks.jsx` (refreshes every 30s while the tab is visible) |
| Taskbar (`initial-build-45adb6`) | uncommitted in the existing worktree, next to David's own uncommitted work | `supabase/migrations/202610300001_psa_sync.sql`, `supabase/functions/psa-sync/index.ts`, `supabase/functions/_shared/psa-sync.mjs`, `scripts/psa-sync.test.mjs`, `supabase/tests/psa_sync.sql`, a `[functions.psa-sync]` block added to `supabase/config.toml` |

### How it works

```
PSA save ──commit──> wake worker ──> agent-api PATCH/POST (revision-checked) ──> Taskbar tasks
   ^                  (and a 20s timer)                                              │
   │                                                                  trigger queues psa_sync_outbox
   │                                                                  pg_net wakes psa-sync (+1 min cron)
   └── POST /api/integrations/taskbar/webhook  <── HMAC-signed snapshot ── psa-sync function
```

- **PSA to Taskbar.** Saves never wait on Taskbar. After a commit that touches `sales_tasks`, a background thread wakes and pushes every task whose `version` is ahead of its `sales_task_links.psa_version`. The thread also runs every 20 seconds, so bulk reassignment (which bypasses ORM events) still syncs. A Postgres advisory lock means only one gunicorn process pushes at a time. While a push is in flight only the link row is locked, never the task row, so a rep's save is never blocked. Failures back off from 30 seconds up to 30 minutes, and a 429 waits 60 seconds.
- **Taskbar to PSA.** A trigger on `public.tasks` queues one coalesced outbox row per task in a synced program. `pg_net` wakes `psa-sync` right away, and a one-minute cron job is the fallback. The function signs the task's *current* row and POSTs it to PSA. PSA upserts the linked task.
- **User mapping.** Matched by email. PSA calls `psa-sync/directory` (signed) every 10 minutes to get the active Taskbar members with Sales access. A webhook that carries an unknown assignee also maps by `assignee_email`. Stored in `taskbar_user_links`.
- **Loop prevention.** PSA records the Taskbar `revision` returned by each write. A webhook with a revision at or below that is an echo and is ignored. A snapshot that matches the PSA values changes nothing and does not bump `version`. When our own create echoes back before its response is stored, it is matched through the `[psa-task:ID]` marker in the description, and the handler waits on that link row's lock.
- **Conflicts** are last writer wins. When the worker first sees an unpushed PSA change it stamps `dirty_at`. A Taskbar change with `updated_at` after `dirty_at` wins and is copied into PSA. An older one loses, and PSA overwrites it on the next push. A 409 from the agent API is resolved by the same rule.
- **Lost create responses** (timeouts) do not duplicate tasks. Before every create, the worker searches Taskbar for the marker and adopts any copy it finds.

### Field mapping

| PSA | Taskbar | Notes |
| --- | --- | --- |
| `title` (240) | `title` (140) | Long titles are cut to 137 characters plus "...". The cut version coming back does not overwrite the full PSA title. |
| `due_at` | `due_at` | Sent as UTC `Z`. An undated PSA task is sent with a deadline 7 days after creation at 17:00 UTC (Taskbar requires one) and stays undated in PSA. |
| `status` open / completed | Not Started, In Progress / Completed | In Progress maps to open. If Taskbar says In Progress, PSA edits keep it at In Progress. |
| `priority` high / normal | High / Medium, Low | Low maps to normal. If Taskbar says Low, PSA edits keep it at Low. |
| `user_id` | `assignee` | Mapped by email. An unmapped owner waits (retried every 10 minutes). |
| `school` | description line `School: ...` | Set on create only. |

PSA rules still apply to Taskbar edits. An open task stays with its school's owner. Reopening or reassigning a school task to someone else in Taskbar is reverted, and the PSA values are pushed back. The status endpoint shows the reason. A task created in Taskbar's Sales program for a mapped assignee becomes a school-less PSA task. One with no assignee (open pool) is ignored until it is assigned.

## Configuration

### PSA (Render `psa-sales-backend`)

| Variable | Value |
| --- | --- |
| `TASKBAR_SYNC_ENABLED` | `true` to turn on both directions. Anything else means off. |
| `TASKBAR_API_URL` | `https://mlsxmivbfnabqtfrlmdg.supabase.co/functions/v1/agent-api/v1` |
| `TASKBAR_API_KEY` | Taskbar API key with **write** access, created by an **Admin** (Admins can assign to anyone) |
| `TASKBAR_SYNC_URL` | `https://mlsxmivbfnabqtfrlmdg.supabase.co/functions/v1/psa-sync` |
| `TASKBAR_WEBHOOK_SECRET` | Random 64-hex shared secret. Same value as Taskbar's `PSA_SYNC_SECRET`. |
| `TASKBAR_SALES_PROGRAM_ID` | UUID of the Taskbar Sales program (from `GET /programs`) |
| `TASKBAR_TIME_ZONE` | optional, default `America/New_York` (display zone for new Taskbar tasks) |
| `TASKBAR_SYNC_POLL_SECONDS` | optional, default 20 |
| `TASKBAR_SYNC_WORKER` | optional. Set `false` on a process that should only answer webhooks. |

All four URLs must be `https://`, or the sync stays off.

### Taskbar function secrets (`psa-sync`)

| Secret | Value |
| --- | --- |
| `PSA_SYNC_SECRET` | same value as `TASKBAR_WEBHOOK_SECRET` |
| `PSA_SYNC_CRON_SECRET` | a second random 64-hex value (used for wakeups and cron only) |
| `PSA_WEBHOOK_URL` | `https://psa-sales-backend.onrender.com/api/integrations/taskbar/webhook` |
| `PSA_SYNC_PROGRAM_IDS` | the Sales program UUID (comma-separated if ever more than one) |

## Approval-gated release steps (David runs these)

Order matters. PSA must accept webhooks before Taskbar starts sending them.

1. **Taskbar agent API is a prerequisite.** Per `AGENT_API_SETUP.md` it is not deployed yet. Apply `202610270001_agent_api.sql`, run `supabase/tests/agent_api.sql`, then deploy:
   ```powershell
   npx supabase functions deploy agent-api --project-ref mlsxmivbfnabqtfrlmdg --no-verify-jwt
   ```
   Publish the Taskbar frontend so the **Settings → AI & integrations** key screen exists.
2. **In Taskbar:** create the program **Sales** (or reuse it), grant every rep access, and confirm each rep's Taskbar sign-in email matches their PSA email. Create an API key as an Admin with **write** access and a 90-day expiry. Get the program ID:
   ```powershell
   Invoke-RestMethod -Uri "$env:TASKBAR_API_URL/programs" -Headers @{Authorization="Bearer $env:TASKBAR_API_KEY"}
   ```
3. **Generate the two secrets** in your own terminal. Keep them out of chat and commits:
   ```powershell
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
4. **Taskbar database.** In the SQL Editor, run `supabase/migrations/202610300001_psa_sync.sql`, then `supabase/tests/psa_sync.sql` (it rolls back; expected result: no errors). The trigger does nothing until step 9.
5. **Taskbar function.** Save the four secrets in a private ignored file such as `.env.psa-sync.local`, then:
   ```powershell
   npx supabase secrets set --project-ref mlsxmivbfnabqtfrlmdg --env-file .env.psa-sync.local
   npx supabase functions deploy psa-sync --project-ref mlsxmivbfnabqtfrlmdg --no-verify-jwt
   ```
6. **PSA database.** In the PSA Supabase SQL Editor (`dlnfvtudzyyabixedniz`), run `api/migrations/20261030_taskbar_sync.sql`. It only adds tables and is safe while the old code runs. If the launch data reset truncates `sales_tasks`, run it after the reset. The links cascade either way.
7. **PSA code.** Merge `feature/taskbar-sync` into `feature/psa-sales-platform` (and the frontend `feature/taskbar-sync-refresh` into `design/psa-sales-platform`), then follow the normal release. Pushing to main deploys. Deploy with `TASKBAR_SYNC_ENABLED` unset first.
8. **PSA env.** Set the PSA variables above in Render with `TASKBAR_SYNC_ENABLED=true`, then redeploy. When the sync turns on, every open PSA task is created in Taskbar (completed history is not backfilled). A create costs 2 requests, so expect about 30 tasks per minute.
9. **Taskbar activation.** In the Taskbar SQL Editor, replace the placeholders locally and run this. Do not save it to the repo:
   ```sql
   insert into public.psa_sync_programs(workspace_id,program_id) values('<WORKSPACE_ID>','<SALES_PROGRAM_ID>');
   select vault.create_secret('https://mlsxmivbfnabqtfrlmdg.supabase.co/functions/v1/psa-sync','psa_sync_url');
   select vault.create_secret('<PSA_SYNC_CRON_SECRET>','psa_sync_cron_secret');
   select cron.schedule('psa-sync','* * * * *',$$select net.http_post(
     url:=(select decrypted_secret from vault.decrypted_secrets where name='psa_sync_url'),
     headers:=jsonb_build_object('Content-Type','application/json','x-cron-secret',
       (select decrypted_secret from vault.decrypted_secrets where name='psa_sync_cron_secret')),
     body:='{}'::jsonb)$$);
   ```
   `pg_net` and `pg_cron` must be enabled (they already are if push reminders are set up).
10. **Verify** with two test tasks and no real reps involved:
    - As an admin, `GET /api/integrations/taskbar/status` should show `enabled: true`, `mapped_users` close to the rep count, and no `recent_errors`.
    - Create a PSA task. It should appear in Taskbar Sales within about 20 seconds. Mark it In Progress in Taskbar, edit the title, then complete it. PSA should match within about a minute (the Tasks page refreshes every 30 seconds).
    - Create a task in Taskbar Sales assigned to a rep. It should appear in that rep's PSA tasks.
    - Check `psa_sync_outbox` in Taskbar for rows with `last_error`, and Edge Function logs for `psa-sync`.

## Rollback

- **Stop both directions immediately:** set `TASKBAR_SYNC_ENABLED=false` in Render and redeploy. The webhook then returns 503. Taskbar retries with backoff for a few hours, then gives up after 12 attempts.
- **Stop Taskbar from sending:** `delete from public.psa_sync_programs;` and `select cron.unschedule('psa-sync');`
- **Revoke** the Taskbar API key in Settings → AI & integrations.
- **Remove entirely** (data in both apps is kept; only the link bookkeeping is lost):
  - PSA: `DROP TABLE sales_task_links, taskbar_user_links;` and revert the 3-line hook in `api/api.py`.
  - Taskbar: `drop trigger tasks_psa_sync on public.tasks; drop function public.psa_sync_enqueue(), public.claim_psa_sync_events(integer), public.psa_sync_directory(uuid); drop table public.psa_sync_outbox, public.psa_sync_programs;` then delete the `psa-sync` function and the two Vault secrets.

## Limits and known gaps

- **Agent API rate limit:** 60 requests per minute per key. An update costs 1 request and a create costs 2 (marker search, then POST). A 409 conflict adds a GET. Reassigning 100 schools' tasks at once takes about 2 minutes to drain. Use one key per PSA environment.
- **Key expiry:** Taskbar keys last at most 90 days. When the key expires, pushes fail with 401 (shown on the status endpoint) until a new key is set. Put a calendar reminder at about 80 days.
- **Deletes:** neither app's API deletes tasks. A task deleted in Taskbar, or moved out of Sales, is detached: PSA keeps its copy and stops syncing it. A PSA task removed by a data reset leaves its Taskbar copy behind.
- **Not synced:** Taskbar description, subtasks, location, and reminders; PSA school links on Taskbar-created tasks; PSA activity history.
- **Notifications:** Taskbar sends its normal assignment push notification when a synced task is assigned. With the backfill, reps may get one per open task.
- **One PSA environment per Taskbar program.** Staging and production must never point at the same Sales program, because task markers would collide.
- **Clock skew:** signed requests are accepted for 5 minutes either side of the receiver's clock.
- **Freshness:** PSA to Taskbar takes about 1 to 20 seconds. Taskbar to PSA is immediate through pg_net, or up to 1 minute through cron. The PSA Tasks page then shows it within 30 seconds. The Home and school pages refresh on navigation only.

## Test coverage

- PSA: `python -m pytest api/tests -q`, 163 passed (28 new in `test_taskbar_sync.py`). Covers mapping, signatures (including a byte-for-byte vector shared with Taskbar), echo suppression, the create-echo race, both conflict outcomes, 409 handling, lost create responses, backoff and 429, detach, school-owner reverts, directory mapping, and the admin-only status endpoint. No network.
- Also checked locally against PostgreSQL 16: the PSA migration applies, the advisory lock makes a second process skip, the batch pushes, and the lock is released.
- Taskbar: `node scripts/psa-sync.test.mjs` passes and `scripts/agent-api.test.mjs` still passes. Every Taskbar migration plus `program_access.sql`, `agent_api.sql` and the new `psa_sync.sql` run cleanly on a PostgreSQL 16 container using the CI bootstrap.
- **Not verified:** the Deno function on Supabase, pg_net wakeups, Vault and Cron, real agent API latency, and Render's multi-process behavior. These need staging. Optional: add `node scripts/psa-sync.test.mjs` and `psql -f supabase/tests/psa_sync.sql` to Taskbar's `.github/workflows/validate.yml`. That file has uncommitted edits, so it was left alone.
