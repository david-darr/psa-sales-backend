# Seasonal program commissions

Production release in progress, 2026-10-29. The migration is applied; code deployment follows.

## Source and reviewed baseline

Christopher's email, **How sales commission works + making sure the sales website tracks it**, dated 2026-10-28 (Gmail Message-ID `<CAFOEw-ZYgx3-D=FLQo00fyR+C0AbDF5xyir9_dEnZkp63yPLTg@mail.gmail.com>`).
The referenced OG Rev Mock Up spreadsheet returned permission denied to the connected Google account. No spreadsheet rows were imported or inferred.

Reviewed the current local branches against freshly fetched origin/main: backend `ca28d48`, frontend `e8c8cf6`. This includes Claude Code's commissions, join links, agent API, school imports, automatic follow-ups and support work. The seasonal module replaces the old commission/close interface and its three API routes. Unused legacy columns and the empty split table are retained for rollback compatibility; no school or user data is deleted.

## Policy

One record identifies a school, season and program. A returning program gets a separate renewal record; editing the school does not overwrite earlier seasons.

1. Gross is confirmed program revenue, in USD.
2. If registered through LeagueApps, fee = Gross x 3.5%, rounded to cents; otherwise fee = 0.
3. Net = Gross - fee.
4. Commission base = Net - cash expenses.
5. Pool = base x 15% for a new sale, or 7.5% for a renewal, rounded to cents.
6. Rep payout is an explicitly agreed dollar amount between 0 and the pool.
7. Sales Director remainder = pool - rep payout.

Example: Gross $10,000; fee $350; expenses $650; base $9,000; new-sale pool $1,350; rep payout $900; Director remainder $450. With the same inputs, a renewal's pool is $675.

Chris did not specify an individual rep rate or a default split. The old rep default rate therefore does not populate seasonal payouts. Blank payout means **awaiting allocation**, not zero: the whole pool is shown as unallocated, with no Director remainder recognized. Zero payout explicitly allocates the full pool to the Director. The full-pool button supports Chris receiving the whole commission when he is the rep.

Sale type is explicitly selected by an administrator; its rate is automatic. The app cannot safely infer whether historical school programs are new or renewals. No season dates are guessed from close dates. No legacy deal value is copied into Gross.

All server arithmetic uses Decimal with ROUND_HALF_UP at fee and pool steps. Inputs require nonnegative cents; expenses cannot exceed Net and payout cannot exceed the pool. Values are allocations, not payment records or a claim that cash was disbursed. Confirm these rounding/negative-margin conventions against the workbook when access is available.

## Interface and API

Sales admin now has Ownership and Commissions. Commissions supports create/edit, season and rep filters, totals by rep and season, CSV export, correction history and reversible voids. Voided records remain visible and keep their history, but do not contribute to totals.

- `GET /api/admin/program-commissions` (`season`, `rep_id`, `format=csv` optional).
- `POST /api/admin/program-commissions` creates a program record.
- `PUT /api/admin/program-commissions/{id}` replaces a record's editable fields, requiring its current integer `revision`.
- `GET /api/admin/program-commissions/{id}/history` provides before/after snapshots and actor IDs.

All routes require administrator login. Unique school/normalized-season/program keys prevent double entry, including voided records. Updates lock the row and reject stale revisions. Audit events are saved in the same transaction. School and rep names are retained if their linked records are deleted; financial records are not cascaded away. CSV text is protected against formula injection.

Legacy closes and the old rate/close API routes are removed at David's request. Existing school stage, owner and closed-by tracking remain in the school workspace and portfolio.

## Verification and rollout

Local SQLite backend suite: 208 passed, including 10 new seasonal commission tests and a regression check that the retired commission routes return 404. Four net tests were removed when the obsolete commission implementation was retired. Frontend lint: no errors, two existing Fast Refresh warnings. Production build and employee/admin demo contracts pass. `node scripts/check-commissions.mjs` exercises the seasonal preview, rounding, unallocated pools, filters, corrections, stale updates, CSV and authorization without network requests.

The new UI has not had a rendered browser check. The migration was applied to production Postgres via the existing Supabase CLI account's Management API login. Both tables have RLS enabled and no anon/authenticated table privileges. Preflight confirmed zero legacy splits or deal values. No school/user data was changed and no email was sent.

Applied `api/migrations/20261029_program_commissions.sql`; verified its constraints and access rules. Deploy the backend before the matching frontend. No new secrets are required. Verify one example with Chris against his workbook before entering historical seasons. Post-deploy authenticated admin acceptance remains required; public HTTP checks only confirm route availability and access enforcement.

For local review, use the frontend dev server and open `/admin?preview=1&scenario=admin`, then choose Commissions. The records there are fictional and all actions stay in the local preview.
