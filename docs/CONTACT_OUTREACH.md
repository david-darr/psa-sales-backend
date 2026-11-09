# Contact outreach: item 4 local draft

Item 5 supersedes this historical checkpoint's web-thread and unscheduled-cadence statements: see [DURABLE_SEQUENCES.md](DURABLE_SEQUENCES.md). The current local draft requires the separate durable worker for all sends and adds explicitly authorized 4/10/17 sequences. Production remains unchanged.

2026-11-05. Backend: `psa-contacts`, frontend: `react-with-flask/frontend`, both `feature/contact-foundation`. Items 1–4 and the accepted upload-button polish remain local and uncommitted. Nothing is pushed, deployed, migrated on production or actually emailed.

## Review

Paste into your own browser, outside the Kairos web view:

http://127.0.0.1:5173/emails?preview=1&scenario=admin

The existing Vite server listens on 127.0.0.1:5173. Demo data and simulated sends stay in the browser. The contained browser has rejected this localhost port, so no rendered desktop/mobile review is claimed. Build/lint and employee/admin demo contracts are checked.

Choose schools, choose a contact audience, choose a template or edit the message, resolve shared-school contexts, then approve the rendered recipients. Add/label contacts on a school page to test PTA, principal, enrichment and Trunk-or-Treat audiences. Existing unclassified contacts appear only under All contacts. School selection is capped at 100; expanded contact mailboxes must also fit the 100-recipient review cap.

## Behavior

- Canonical contact identities drive recipient resolution. Each matching mailbox receives one message, never a CC list. Roles are school-specific; Trunk-or-Treat uses a tag. A mailbox linked to several selected schools requires an explicit school choice before sending. Merge fields use that association's name and school. Private school associations outside the sender's ownership are never exposed by the preview.
- Selecting a school is separate from selecting a mailbox. A suppressed primary address or previously contacted school does not hide another valid contact. The review applies the actual contact eligibility, campaign, recent-contact and merge-field checks. A school's closed/replied stage still blocks prospecting; conversation replies use their own reviewed path.
- New contact reviews are actor-bound, stored for 15 minutes, single-use and idempotent. They bind the complete request, resolved recipient set, chosen school, contact/link/ownership versions, rendered copy, template revision and exact attachment fingerprints. Changed data invalidates approval; workers recheck current ownership/contact/suppression before sending.
- A unique database ledger reserves `(campaign, contact, step)`. Sorted canonical contact locks serialize overlapping requests across reps. Replayed approval returns the existing batch. Definitely unsent failures/cancellations can be reviewed again; an unconfirmed attempt remains protected. Retrying an older batch whose reservation has been replaced cannot send it.
- Standard outreach includes historical introductions conservatively. A distinct campaign is an explicit admin action with a recorded reason and per-rep cap. It does not override suppression, closed stages or the recent-contact cooldown. A new campaign can support an intentionally reviewed new-season intro after the school's stage has been reset appropriately. Follow-ups stay linked to the campaign's original conversation; historical standard conversations remain usable when unambiguously school-linked.
- Every manual send needs review, including compatibility batches. The synchronous `/api/send-email`, `/api/send-followup`, `/api/send-custom-email`, `/api/send-custom-email-bulk`, `/api/send-custom-reply` and `/api/crm/outreach/send` endpoints now return authenticated `409 review_required`. The current UI uses reviewed queues; external clients using retired endpoints must migrate. Signed legacy school previews can queue primary-recipient compatibility batches under the same contact ledger and worker safeguards.
- Replies are reviewed, queued, quota-counted and addressed by the server to the original conversation contact from the original sender. They retain thread headers and log a reply rather than a new introduction. Reassigned schools and suppressed contacts are rejected.
- Test-to-myself first previews the school example, then queues only to the signed-in sender's own stored email. Its approval is idempotent and purpose-bound. Tests count toward the allowance and have batch/attempt audit, but create no school activity, sent conversation, enrollment, stage change or follow-up eligibility.
- The effective allowance is the lower of platform `OUTREACH_DAILY_LIMIT` (default 150), optional `OUTREACH_MAILBOX_DAILY_LIMIT`, and the campaign's per-rep cap. Successful intros, replies, follow-ups, tests, pending reservations and unconfirmed attempts consume the appropriate allowance. Resending an unconfirmed message does not erase the earlier attempt's usage or audit. Day boundaries are midnight America/New_York, correctly including 23/25-hour DST days. Manual messages are not restricted to weekday business hours; future scheduling will be.
- Sends use groups of at most five, refreshing the inbox before continuing. An incomplete/backlogged/failed check pauses remaining messages. Follow-ups also require a current successful sync before queue and before send; the existing 3/7-day boundaries and 90-day maximum are enforced. The stored 4/10/17 template suggestions are not scheduled yet.
- An SMTP 5.1.1 hard rejection suppresses that mailbox and pauses the rest of the batch. Matched IMAP delivery reports require the stored original Message-ID plus exact final recipient and permanent 5.1.1 status. They do not count as human replies. A matched human stop request suppresses and cancels pending contact steps; appropriate open schools become not_interested. Ambiguous negative replies stop for admin review instead of continuing. Quoted history is excluded from phrase matching.
- Feedback also finds a contact already sent earlier in an active batch and pauses its remaining messages. Manual Report stop / complaint on a school contact records the source and actor, suppresses globally and pauses affected batches. Only an admin can clear suppression through the existing reasoned contact edit.
- A retry/resume needs a fresh sender-owned preview of the remaining frozen messages. Unconfirmed resends require explicit selection and the UI acknowledgement to check Sent mail. Pause reasons, remaining counts and prior unconfirmed attempt history stay visible. Admin visibility does not authorize sending from another rep's mailbox.

## Review mode changes automation

This draft intentionally stops the old in-process day-3/day-7 automatic sender from manufacturing approval. Due work remains visible and manually reviewable. This is LOCAL behavior until release; production settings were not changed. The next planned item is persisted, configurable campaign sequences and an explicitly authorized automatic mode with a separate durable worker. No automatic enrollment, new schedule, agent send permission, paid hosting or outbound notification was provisioned here.

## Feedback and delivery limits

SMTP acceptance is not inbox delivery. A message already in SMTP can finish after a stop signal. IMAP detects reports only when fetched, cannot see every Google complaint, and has no configured provider complaint feed. The UI states this coverage and offers manual reporting. No exactly-once guarantee is claimed: uncertain outcomes are retained and never blindly retried. The batch worker still runs in a web-process thread; durable scheduling/restart recovery belongs to item 5. No live Gmail, hosted quota, actual complaint feed or production deployment was exercised.

## Verification and repeatability

- Full backend suite: 282 tests (26 contact-outreach tests) pass. Earlier endpoint tests now assert retirement; SMTP credential and follow-up worker coverage uses reviewed batches. Existing helper tests still exercise message assembly and SMTP reuse.
- `check_contact_outreach_postgres.py`: guarded disposable PostgreSQL 17, migration twice, RLS/public privilege checks on all five new tables, cross-rep reservation race, four-way approval replay, concurrent retry/complaint with no deadlock or suppressed delivery, and school deletion that preserves send/ledger history. Real TCP fake SMTP: one small batch of 5 and 12 concurrent reps × 100 contacts = 1,200 messages, all once, audit matched. Final local heavy run 14.75 seconds with ordinary API p95 of 52 ms. No remote throughput claim.
- Frontend lint: zero errors, two existing Fast Refresh warnings. Production build passes with the existing MapLibre chunk warning. Employee/admin, contacts, ownership, templates, catalog, commissions and new contact-outreach demo contracts pass; global fetch is blocked in demo checks.

Commands:

```text
python -B -m pytest api/tests -q --disable-warnings
# Requires explicitly supplied disposable loopback DB psa_contact_outreach_test:
python -B api/tests/check_contact_outreach_postgres.py
npm run lint
npm run build
node scripts/check-contact-outreach.mjs
node scripts/check-contact-outreach.mjs --admin
```

The older `load_outreach.py` CLI scenarios are retired because their unsigned send/unreviewed retry contract changed. Its fake TCP SMTP fixture is reused by the current guarded runner. Never point either fixture at Supabase or Gmail.

## Release boundary

Separate authorization is required for commits/pushes/migrations/deployment/real mail. Recheck remotes first; Claude Desktop's unrelated work in `psa-due-followups` remains untouched. Pause and settle/review existing batches before a future cutover; do not automatically resume old sending rows.

After local acceptance, stage the full migration sequence: contacts, shared templates/catalog, school ownership, then `20261105_contact_outreach.sql`. The last adds batch/contact context fields, campaigns, private reviews, the dedupe ledger, feedback events and durable send attempts. Verify all five new tables' RLS and revoked public grants before backend then frontend release. It neither infers historical campaign membership nor sends anything. Review the old automatic-follow-up switch and explicitly accept the review-mode transition before release. A real internal-recipient Gmail test still needs authorization and a person to confirm receipt.
