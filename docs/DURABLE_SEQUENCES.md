# Durable follow-up sequences: item 5

Local draft, 2026-11-05. Backend: psa-contacts; frontend: react-with-flask/frontend; both feature/contact-foundation. No production change, real mail, commit, paid provisioning or hosted worker activation.

## Product behavior

- Outreach > Sequences: admins define versioned sequences with matching audience/step templates and saved catalog PDFs. Employees search/paginate their own recent, unanswered introductions, review every rendered message and explicitly enroll. Intro sends never enroll themselves. Own enrollment history is paginated, with pause reasons and revocation.
- Default cadence is calendar days 4/10/17 from the intro, preserving Eastern local time across DST. Weekends shift to the next weekday and sends stay inside the chosen weekday business window (default 9–17 America/New_York). Subsequent overdue steps wait at least one local calendar day after the actual previous send; there is no catch-up burst.
- Review mode is default and requires fresh 15-minute approval for each due step. Automatic mode requires an additional explicit sender authorization for the frozen messages, contacts and start/end dates (within 90 days). Admins cannot authorize another employee's mailbox. No agent send scope was added.
- Enrollment review is stored, actor-bound, expires after 15 minutes and commits idempotently. Source/contact/link/ownership/template changes invalidate approval. Template edits and sequence version changes never silently change approved copy; definition edits/archive pause active enrollments.
- Replies, closed stages, ownership changes, suppression, incomplete mailbox checks, expired authorization or invalidated templates block dispatch. Moving a school back to an open stage does not revive its stopped enrollment. Revocation prevents remaining sends; an already in-flight SMTP message can finish.
- Existing sent steps are carried forward on explicit replacement. An in-flight step cannot be replaced. Managed originals stay excluded from legacy 3/7-day follow-ups after cancellation. Historical originals need a stored Message-ID; no guessed threading or automatic backfill.
- Sends preserve Message-ID, In-Reply-To and References, use the common campaign/contact/step ledger and caps, and load the frozen PDF assets through the checksum-verified catalog loader. Sequence messages are audited separately from the old follow-up counter.

## Durable worker requirement

**All queued mail in this draft now requires the separate worker, including manual batches, replies and self-tests. The web-process thread fallback has been removed. An API-only deployment leaves mail queued.** No host was provisioned and no real worker was started.

The dedicated process uses database row locks, fenced leases and durable progress. It sends at most five recipients per turn, orders claims by the last batch heartbeat, and refreshes the mailbox before continuing. After restart, definitely unsent work is recoverable; an in-flight attempt becomes unconfirmed and pauses for review. Unknown SMTP outcomes are never blindly resent. A scheduled batch crossing the closing hour is deferred to the next window, without being mislabeled as stalled during that wait.

Run from the backend repo only on an explicitly configured host with the API's database, encryption key and mail/review settings:

```text
python -m api.outreach_worker --poll-seconds 10
```

`--once` performs one bounded cycle. These commands can send approved mail if pointed at real data; neither was started against production. The CLI disables its own in-process reply scheduler. Worker heartbeat/offline state is visible in Sequences and batch progress. Importing modules does not launch a worker.

## Rollout dependencies, not performed

1. Review/reconcile all five local items. Select and approve the worker host and any associated cost; no paid service is assumed.
2. Disable any old deployed `AUTO_FOLLOWUPS_ENABLED` sender and allow in-flight requests to finish before new workers or overlapping releases. An old image does not understand sequence-managed originals and must not continue its independent 3/7-day automatic sending.
3. Apply the prior local contacts, shared templates, ownership and contact-outreach migrations in documented order, then `api/migrations/20261105_durable_sequences.sql`. The additive/idempotent migration protects all six new tables with RLS and revokes public-role privileges. It creates no sequence/enrollment/authorization.
4. Release the compatible API and separately configured worker, verify heartbeat/queue/leases, then release the frontend. Keep automatic enrollments empty during cutover.
5. Conduct a controlled sender-owned Gmail test of threading, PDFs, sync, caps and hosted restart behavior before enabling an approved real sequence. A rollback must preserve the new data and avoid reactivating an older automatic sender.

SMTP acceptance is not delivery and cannot provide exactly-once guarantees. IMAP sees signals only when fetched, has no configured provider complaint feed and may miss complaints outside its coverage. Item 4's feedback limitations still apply. Live Gmail, hosted lifecycle/latency and rendered UI review remain untested.

## Local review

The existing Vite server is running. Open in an ordinary browser:

```text
http://127.0.0.1:5173/emails?tab=sequences&preview=1&scenario=admin
```

The demo supplies a fictional Sequence Preview Academy and templates. It has no sending timer or production network calls. Dates follow Eastern/DST/weekend rules; enrollment and authorization are browser-only simulations. Refresh resets state. The contained browser previously rejected localhost port 5173; no rendered review is claimed.

## Verification

- Backend: 299 tests pass, including default review, explicit automation, expiry/replay, version history, owner/reply/stage changes, three-step threading, restart recovery, no catch-up burst and exact PDF delivery.
- Guarded PostgreSQL 17: migration twice, RLS/grants, concurrent enrollment commits, two schedulers/workers, business-window defer/restart, ambiguous SMTP DATA without resend, and complaint detection between five-message manual turns. Real SMTP sockets connect only to a loopback fake server.
- Frontend build passes; lint has zero errors/two existing Fast Refresh warnings. Existing demo contracts and new employee/admin sequence contracts pass with fetch blocked. The existing MapLibre chunk warning remains.

```text
python -B -m pytest api/tests -q --disable-warnings
node scripts/check-sequences.mjs
node scripts/check-sequences.mjs --employee
```

`api/tests/check_sequences_postgres.py` requires a loopback `SEQUENCE_TEST_DATABASE_URL` with database exactly `psa_sequence_test`. It destroys/rebuilds that disposable schema; never use existing/production data. The disposable container was removed after verification.

Next planned item: bounded employee-scoped agent tooling; not implemented here.
