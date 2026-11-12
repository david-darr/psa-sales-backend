# School Sales and Business Sales

Local feature branch: `feature/school-business-sales`. Not deployed.

## Behavior

- The website has two URL-based workspaces. School Sales keeps its existing URLs.
  Business Sales starts at `/businesses`, with records, sponsorship pipeline,
  sponsors, tasks, discovery, outreach and territory map.
- Each browser tab retains its own area through its URL. Switching areas uses a
  fresh page so a selected recipient list, stale response, or open message review
  cannot follow the user into the other workspace. The existing sign-in remains.
- Businesses use stable existing relationship IDs and contact/mail/task links,
  with an immutable `sales_workspace` discriminator. Existing rows, drafts,
  campaigns, sequences and templates default to `school`; nothing is moved.
- Sponsorship stages use the existing canonical IDs: `pending` (new prospect),
  `contacted`, `replied`, `meeting` (sponsorship discussion), `partner` (active
  sponsor), `former` (former sponsor), `not_interested` (closed).
- Business records add industry and optional sponsorship value in USD. This is
  a relationship amount, not a payment ledger or a school-program commission.
  School commission formulas are not applied to sponsorships.
- Owners/admins manage contacts, notes, next action and stage. Reps can claim
  unassigned businesses; admins can review assignment of all matching records.
  Role and ownership checks are unchanged and apply within both areas.
- Discovery uses business categories and does not load school partner sheets.
  Its save flow can retain a business without an email for phone/visit work.
- Business CSVs accept `business_name` or `company_name` as an alias of the
  legacy `school_name` field. Use `school_type=business` or omit the type.
  Business contact roles include `decision_maker`, `marketing`,
  `community_relations`, `other_staff`, and `unknown`.

## Email boundaries

Templates, sequences, campaign plans, reviews, sends and tasks belong to one
workspace. The PDF catalog, mailbox connection and employee identity are shared.
Business outreach requires reviewed custom copy or a Business Sales template;
the built-in school pitch is never chosen by default. `{business name}` and
`[business_name]` are supported alongside the old merge fields.

Mailbox quotas, uncertain-attempt accounting, contact reservations, inbox sync,
and global opt-outs span BOTH areas. A record-only stop remains local to that
school/business; an email-wide stop applies everywhere. Existing send/retry
reviews, owner guards, expiry, human approval and kill switches remain required.
Background workers derive their area from persisted parents, not UI preference.
The SMTP worker rechecks that its batch and recipient relationship share an area.

## HTTP and AI clients

Use `X-PSA-Workspace: school|business` (or `?workspace=...`) per request. Omitting
it retains School Sales for existing clients. This selects data; it never grants
permissions. Do not accept an area change through record editing.

Generic endpoints and legacy ID/field names remain compatible. Serialized rows
include `sales_workspace`, `record_name`, and a `business_name` alias for business
records. Distinct AI operations are `psa_businesses`, `psa_business`,
`psa_create_business`, and `psa_edit_business`. Existing fixed operations accept
`workspace`; generic task, contact, draft, campaign and sequence MCP tools also
support an explicit per-call area. Final approval remains a private human action.

PSA Command's draft source includes an area selector, separate overview caches,
workspace-bound private reviews and template uploads, and matching MCP tools.
Its source-only update does not replace connections, API keys, or human-session
data. The local distribution zip must match the Store source before publication.

## Release order

1. Back up production. Apply `20261112_school_business_sales.sql` before any new
   backend/worker code; it adds checked/defaulted columns to 15 existing tables
   without altering grants, RLS, approvals or account records.
2. Deploy backend and worker together, then frontend. Keep the existing campaign
   automation configuration; this release needs no new paid service or worker.
3. Publish PSA Command after the compatible backend is live. Update source files
   through the existing installer; do not uninstall or clear connections.
4. Verify both areas with real employee/admin sessions: independent counts,
   discovery, empty-email prospects, assignment/claim, imports, contacts and map.
   Run a human-controlled self-test email before a real business campaign.

Before business data exists, an older code rollback can ignore added columns.
After businesses exist, do not roll back to a backend that lacks area filtering:
it would treat the business rows as schools. Retain the boundary in any rollback.

## Verification

- Backend regression suite and dedicated cross-area/role/SMTP/native-AI tests.
- `python -B -m api.tests.check_workspace_postgres` against an EMPTY disposable
  localhost DB named `psa_workspace_test...`, selected only through
  `PSA_WORKSPACE_TEST_DATABASE_URL`: checks migration twice, legacy preservation,
  RLS retention and PostgreSQL query scoping. Never run against Supabase.
- `node --test integrations/psa-mcp.test.mjs` uses fake HTTP only.
- Frontend build/lint, all existing demo scripts and `check-business-sales.mjs`.
- Rendered browser review remains pending: Kairos's contained browser did not
  open localhost. No production schema/data changes or real sends were made.

### Follow-through review

- Business Team statistics use business labels and link to the matching rep's
  businesses. The business list accepts an explicit owner filter and exposes
  reviewed assignment across all matching businesses.
- Direct website requests and delegated AI operations use the same school-only
  reference-source guard. Business calls cannot read the school directory or
  read/refresh the school partner-sheet map layers.
- Worker regression tests exercise business campaign approval/dispatch and
  threaded sequence dispatch without an HTTP context. Their batches and mail
  history remain business-scoped, and school-context approval is rejected.
- Current checks: 425 backend tests pass; frontend build, lint (two existing
  Fast Refresh warnings), and business demo contracts pass. No real sends or
  production changes. Rendered browser review remains pending.
