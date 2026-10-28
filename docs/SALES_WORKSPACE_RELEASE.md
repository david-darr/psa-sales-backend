# PSA Sales workspace release draft

This is local work for review. No migrations from this draft have been applied to production, and neither draft branch has been pushed.

## Checkouts

- Frontend: `C:\Users\David\Documents\Random Coding Projects\psa test\react-with-flask\frontend`, branch `design/psa-sales-platform`.
- Backend: `C:\Users\David\Documents\Random Coding Projects\psa test\psa-due-followups`, branch `feature/psa-sales-platform`.
- Both include the earlier reply-sync/school-workspace draft. The production Finder hotfix is carried in the local backend changes. Reconcile against current `origin/main` before committing or releasing.

## Product changes

- Dark workspace (charcoal cards, hairline borders, mono labels, coral accent, white pill primary buttons), global school search with Ctrl/Cmd K, responsive navigation, and page code loaded on demand.
- Accounts (`/portfolio`): which schools belong to which sales rep. Each rep card shows active clients, former clients, pipeline size and closes in the last 90 days, with a per-school list that links to the school and to the map. Administrators see every rep. Employees see only their own accounts. CSV export. "Closed" means the school reached Active client or Former client; the school page shows who closed it and when. Needs `20261029_accounts_portfolio.sql` (`closed_at`, `closed_by_id`).
- Territory map: MapLibre with the OpenFreeMap dark basemap, clustered points colored by owning rep, owner and stage filters (deep links `/map?owner=&stages=&school=`), account cards, and a "Locate them" action for schools without coordinates. Shows an explanatory message when WebGL is unavailable.
- Admin access: administrators can grant or remove admin on the Team page (`PATCH /api/crm/team/<id>`). They cannot change their own role and at least one admin must remain. Rep-wide visibility (Accounts, Map owner filter) requires admin.
- Find schools: rebuilt search with a map and result list, save to your own accounts, and already-owned indicators showing the current owner.
- Outreach: rebuilt as Compose (Intro or Custom), Follow-ups, Inbox, History and Add tabs. Compose is a step flow (recipients, message, review, send) that sends in tracked batches with progress and resume. Per-day sending limits and mailbox status are shown up front. Needs `20261029_outreach_batches.sql`.
- Overview: scoped pipeline counts, tracked outreach and response rate, 14-day outreach chart, open/overdue tasks, next school actions, and activity. No invented sales values or growth comparisons.
- Schools: server-side search, stage/type/owner/action filters, pagination, CSV export of the current page, and atomic bulk stage/owner updates. Administrators can assign schools across the team. Employees can act on their own schools.
- Pipeline: six stages, bounded 25-card columns with full-list links, drag/drop and keyboard-accessible stage menus.
- Tasks: persistent employee assignments, due dates, priorities, completion/reopening, rescheduling, and stale-update protection. Open linked tasks transfer with a school’s owner. Task due dates use the viewer’s calendar day; outreach reporting uses UTC.
- School workspace: editable contacts/notes, owner/stage controls, next action, linked tasks, activity logging, and conversation history.
- Outreach: focused recipient/reply/follow-up/history/import tabs. Recipient selection and personal sent history are scoped to the signed-in sender. Template review shows personalized messages and attachments. Signed reviews expire after 15 minutes and detect content/recipient changes before sending.
- Team: one grouped query for assignment, outreach, response, and overdue-task counts. Invitations remain administrator-only. No arbitrary performance rankings based on email volume.
- Discovery: save a search result to outreach, team-assignment hints, bounded provider timeouts/errors, and a suggested visit order for 2–25 stops. The route uses geographic distance, not road or traffic information.
- Map: persisted snapshots, coordinate reuse, retained last-known coordinates during provider failures, administrator-only bounded refresh batches, and layer filters. The frontend can stop between refresh batches and resume later.
- Settings: editable name/phone, email connection setup/checking, invitations, and the existing encrypted-credential migration control. The unused Google OAuth/maps frontend packages and Google script provider were removed; sign-in remains PSA email/password.
- Demo: fictional employee/admin/new-hire scenarios, editable school/task/activity fixtures, and blocked email sending. Demo changes reset on refresh and do not call production APIs.

## Development and review

From the frontend checkout:

```powershell
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

- Admin demo: `http://localhost:5173/?preview=1&scenario=admin`
- Employee demo: `http://localhost:5173/?preview=1&scenario=employee`
- New employee demo: `http://localhost:5173/?preview=1&scenario=new`

The demo is available only in Vite development mode. The production bundle excludes its fixtures. Regular development requests use Vite’s local Flask proxy at port 5000. `VITE_API_BASE_URL` can override this; production still defaults to the existing Render backend. Use a separate test database for real development.

Check overview/task/pipeline navigation, create/complete/reschedule a task, bulk-update selected schools, reassign a school as an administrator, log a call, save a discovery result, and inspect a template review. Sending is disabled in every demo scenario.

Verified locally: 130 backend tests, frontend lint (0 errors, 2 fast-refresh warnings) and build, employee/admin demo contracts, and rendered dark-theme screenshots of the main pages, Accounts, Outreach, the map and Find schools in the admin demo. The production-build map worker and a live mailbox send are not yet verified in a real browser.

Automated checks from the backend:

```powershell
python -m pytest api/tests -q --disable-warnings
```

From the frontend:

```powershell
npm run lint
npm run build
node scripts/check-demo.mjs
node scripts/check-demo.mjs --admin
```

The connected computer tool had no browser available during this implementation. Rendered desktop/mobile inspection and a real account/mailbox acceptance check are still required.

## Database and release order

1. Review and apply `api/migrations/20261005_reply_sync_school_workspace.sql`.
2. Review and apply `api/migrations/20261028_sales_workspace.sql`.
3. Review and apply `api/migrations/20261029_accounts_portfolio.sql` and `api/migrations/20261029_outreach_batches.sql`. Neither has been applied anywhere. Back-fill of `closed_at` for existing clients should be checked after applying.
4. Verify RLS is enabled and `anon`/`authenticated` privileges are absent on all new tables. The migrations are additive, rerunnable, and include lookup indexes.
5. Deploy the backend, verify the new routes with a test employee/admin, then deploy the matching frontend. Old outbound endpoints remain compatible, but administrators must own a school to send outreach to it. Give Ricky admin access from the Team page after deploy.
6. Check task ownership, reassignment, stale task updates, signed message review, reply sync, and a controlled single-recipient send. No real email was sent by the automated tests.

Existing Render database/JWT/encrypted-mail settings remain necessary. This draft introduces no new secret. Keep `MAIL_CREDENTIAL_ALLOW_LEGACY=false` after the completed encryption migration. Never replace the existing persistent mail encryption key without a credential migration.

## Independent reply schedule

The backend includes a resumable command intended for a separately configured schedule:

```text
python -m api.sync_mailboxes --budget-seconds 240
```

The command disables its in-process scheduler, checks the least-recently checked mailboxes first, rotates backlogs behind other employees, and prints only counts. Progress is persisted in `mail_sync_states`. Each mailbox check has a bounded batch/time budget. Historical lookback remains 90 days; new tracked conversations match threading headers, while the sender fallback is confined to legacy conversations without recorded outbound IDs.

Configure the hosted schedule separately with the existing backend environment settings. Once its runs are verified, set `PSA_DISABLE_SCHEDULER=true` on the web service to avoid relying on its in-process timer. No hosted job or additional paid service has been created from this draft.

## Remaining operational limits

- SMTP delivery still happens in request batches. The review token protects reviewed content; it does not provide durable delivery jobs or make retries idempotent. A connection failure can leave delivery uncertain. Check history and the mailbox before retrying. A durable send ledger/worker is the next delivery improvement.
- Gmail uses encrypted app passwords. OAuth remains a separate integration and rollout decision.
- Legacy emails do not have reliable historical thread identifiers. Matching is more limited than for new tracked messages.
- Scheduled mailbox checks depend on configuring the hosted job. The in-process fallback alone does not run when the web process is down.
