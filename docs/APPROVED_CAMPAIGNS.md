# Approve-once campaigns: local draft, 2026-11-08

Previous items were committed locally as backend d30c7f3 and frontend 1728ace. This item is a new uncommitted draft. No pushes, production migrations, hosted worker activation or real mail were performed.

## Employee experience in Kairos

1. Sign in inside PSA Command and delegate only the scopes needed. Choose a 7/30/90-day key expiry; default remains 30 days. A 12-hour human session is separate from agent delegation and can be renewed inside Kairos without creating another key.
2. Ask Kairos to prepare a campaign using explicit school IDs, a saved intro template/version, audience, shared-contact school choices, optional sequence/version, daily cap, start date and end date. Current limits are 500 selected schools and 1,000 resolved mailboxes per campaign. Ordinary individual batches retain their smaller limits.
3. Outreach > Campaigns shows the exact recipient snapshot, rendered introduction and follow-ups, saved PDFs, weekdays/Eastern hours, cap, dates and delegation expiry. A newly matching school is never enrolled. Only the sending employee can authorize; an admin cannot approve somebody else's mailbox. An expired delegation stops sending even if the campaign end date is later.
4. Explicitly authorize the frozen campaign once. The dedicated worker dispatches bounded chunks. Only a recorded introduction can create the already-approved follow-up enrollment. Due dates are measured from its actual send time, shifted to business windows. Intros too late to finish the approved sequence are skipped rather than extending authorization.
5. Read operational summaries, pause, resume an employee-paused campaign, or permanently cancel here. Agents can prepare/read/pause/cancel, never approve or resume. SMTP already in flight can finish. No external summary email/Discord destination was configured.

## Enforcement

- Sender identity is derived from the authenticated employee/key. Sender email/name changes, template or sequence revision/archive, shared campaign cap changes, key revocation/expiry, API kill switch, end date and contact eligibility are checked again.
- Employee approval is revision-bound, expires after 15 minutes if not approved, and compares the frozen review while holding the sender/school/contact locks. Refreshing an unapproved plan increments revision. An approved plan's scope cannot be edited: cancel and prepare a new review. User control actions also increment revision.
- Fixed contact and message snapshots survive restarts. Common canonical-contact locks and the durable campaign/contact/step ledger prevent cross-key/reviewer duplicate reservations. Mailbox quota and shared campaign limits are combined with the approved cap, including unconfirmed attempts; several plans do not multiply the allowance.
- Pause is enforced at dispatch boundaries for introductions and follow-ups. Cancel/expiry release definitely-unsent queue reservations and stop associated enrollments, retaining all attempts. Unconfirmed outcomes are not automatically retried. Error/feedback pauses require a new reviewed campaign, rather than resuming an old authorization after changing a status.
- Detected bounce/complaint/opt-out signals affecting an approved contact block other batches in the plan. Signal coverage remains SMTP rejection plus the existing matched IMAP/manual reports, not a promise of instant feedback from every recipient/provider.
- School stop stages persist even if the stage is changed back before the next worker pass. Current suppression, contact/link versions, ownership versions and PDF fingerprints are rechecked. Approval can lose recipients but cannot gain them.
- A persisted dispatch round keeps a large/old campaign from monopolizing each scheduling pass. Paused plans are ordered after active plans. Daily summaries are stored per plan/Eastern day: SMTP-accepted, failed and unconfirmed recipient outcomes; affected contact signals; cumulative replies/skips; outstanding contacts and mailbox allowance. SMTP acceptance is explicitly not inbox delivery.

## API and packaging

Agent base /api/agent/v1:
- GET/POST /outreach/campaign-plans: outreach:prepare.
- GET /outreach/campaign-plans/{id} and /summary: outreach:read; employee-owned only.
- POST /outreach/campaign-plans/{id}/stop with revision and pause/cancel: outreach:send.

Human JWT routes use /api/outreach/campaign-plans, /{id}, /{id}/summary and /{id}/{approve|refresh|pause|resume|cancel}. Agent keys cannot authenticate human approvals. No generic approval/proxy tool is exposed. The source-only integrations/kairos/psa_command.zip contains the updated tab and no sessions, saved connections, keys or app data. Installed source is in the per-user psa_command custom tab folder; Kairos application code was not edited. Source changes require tab fingerprint approval and a restart for already-loaded Python. Changed MCP tools need review in Tool Store.

## Local verification and rollout boundary

339 backend tests and seven Node bridge tests pass. Includes the Kairos private-session path, campaign snapshots, scope/expiry changes, cap/window limits, pause/resume/cancel, sticky stage stops, cancellation releasing unsent reservations, delayed feedback, unconfirmed SMTP outcomes, a 110-contact preview, fair scheduling and threaded follow-ups. Native JavaScript syntax passes. The prior frontend commit passed lint/build and admin/employee approval demo checks; the React app is unchanged in this item.

The disposable PostgreSQL check applies the migration twice, verifies RLS and public-role grants, races human approvals, races scheduling/workers and races cancellation with scheduling. Ten socket-SMTP messages arrive once each; a restarted worker sends nothing cancelled. No Gmail or remote database is used. Rendered review of the native campaign pane is still pending; syntax and API tests are not visual acceptance.

Apply all previous item migrations and then api/migrations/20261108_approved_campaigns.sql before releasing the compatible web API and dedicated worker. CAMPAIGN_AUTOMATION_ENABLED defaults false and must be explicitly enabled as a separate rollout action after controlled employee-owned live testing. Nothing here provisions a worker, connects Chris's installation or authorizes a live campaign. Keep the old automatic follow-up dispatcher disabled during cutover as documented in DURABLE_SEQUENCES.md.

```powershell
$env:PSA_DISABLE_SCHEDULER='true'
python -B -m pytest api/tests -q --disable-warnings
node --test integrations/psa-mcp.test.mjs
# Disposable, destructive test only; the script rejects non-loopback/other DB names:
$env:CAMPAIGN_TEST_DATABASE_URL='<loopback URL with database psa_campaign_test>'
python -B api/tests/check_campaign_plans_postgres.py
```

Next planned item: duplicate-school merging, preserving contacts, suppression, tasks, financial records and approval boundaries. It has not started.
