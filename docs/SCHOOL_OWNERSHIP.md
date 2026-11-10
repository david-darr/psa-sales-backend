# School ownership and reusable template PDFs: local review

2026-11-05: David requested reusable PDF attachments on templates and then item 3 of the campaign plan. Both are implemented locally. Nothing committed, pushed, migrated on production, deployed, invited or sent. Backend psa-contacts and frontend feature/contact-foundation hold the draft. Pre-existing agent API changes in the separate psa-due-followups checkout remain untouched; the new checkout only adds county to the agent filter forwarding list.

## Template PDF extension

Admins upload a PDF once under Outreach / Templates, select it on a saved template, and it attaches on EVERY use without reselecting it. Up to three PDFs, each 10 MB or less and 15 MB total. This explicitly extends the original intro-only plan: follow-up templates may also have an admin-selected PDF, while all Chris source templates remain attachment-free until an admin chooses files. Versions, previews and queued recipients bind the exact immutable asset IDs/bytes. Uploads and downloads are admin-only, private DB assets are RLS-protected, filenames are sanitized and size/type/header limits are enforced. Rep batch-copy editing cannot silently remove or replace a template's saved files. Existing arbitrary all-flyers toggles are not used by shared templates.

GET/POST /api/outreach/template-assets lists/uploads reusable files. GET /api/outreach/template-assets/{id} is an authenticated private admin download. The frontend/demo support PDF uploads and selection. Assets can be reused by several templates; saving a new version does not mutate old file bytes.

## Ownership workflow

- Schools can have user_id NULL, explicitly Unassigned. Existing ownership is not reset or inferred. County filters are case-insensitive exact matches.
- Schools / Unassigned pool is visible to signed-in reps and admins. A rep can atomically claim one school as themselves. Claims cannot name a different employee and cannot take another rep's school. Repeating your successful claim is idempotent.
- Admins can select rows or use Assign all matching, including every matching page. The preview shows total/changing counts, target owner, current owners, county breakdown and up to 20 samples. No ownership changes during preview. Filters are saved server-side and match at most 2,000 schools per review.
- Explicit confirmation uses an actor-bound 15-minute review. Commit locks and rechecks membership, owner/version and displayed school context; stale/deleted/changed records or target employee require a new preview. Repeat commits return the same result. School activity logs include the actor, old/new owner and review ID.
- Ownership changes cancel queued recipients. A sending recipient blocks the whole reassignment rather than changing ownership during SMTP. A monotonically increasing ownership version is bound into preview proof and each new queued recipient. Moving a school away and back cannot resurrect an old approval or failed batch. Existing legacy recipient rows are backfilled; a missing old version fails closed once ownership has changed.
- Open tasks transfer when a new owner is assigned/claims. On release to Unassigned, they retain their existing assignee until a new rep claims the school. Completed task assignment and commission/closing-credit history are unchanged.
- Existing selected-ID bulk updates, workspace PATCH and delegated agent assignment use the same ownership change service. The reviewed full-filter workflow is new; older explicitly selected-ID API workflows remain compatible and audited.
- Unassigned schools remain in Finder deduplication/reference results. Map and Accounts retain them with an Unassigned group. Normal rep lists remain owned-only; the pool is explicit. Sending still requires ownership: admins can claim from the pool as themselves, never silently use another rep's Gmail.
- Team points admins to existing invitation/join-link controls, with rep access by default and admin access granted separately. No employee accounts or invitations were created. Chris's reported production reassignment has not been re-run or independently verified in this local work.

## Routes

GET /api/crm/schools?scope=unassigned&county=Fairfax
POST /api/crm/schools/{id}/claim with an empty object
POST /api/crm/schools/assignment-preview with user_id (integer or null), plus either ids or filters
POST /api/crm/schools/assignment-reviews/{review_id}/commit
GET /api/crm/map-accounts?scope=unassigned&stages=pending,contacted,replied,meeting,partner,former

## Verification

248 backend tests pass. New ownership tests cover scopes, claims, reviewed filtering, stale/expired/wrong-actor reviews, deleted targets, owner epochs/old approvals, queued cancellation, atomic in-flight rejection, map/portfolio inclusion and ownership access. Upload tests cover reusable multi-PDF sends, explicit follow-up PDFs, limits, sanitized names, deduplication and private downloads.

Disposable local Postgres 17: migration twice, RLS/public grants, competing claims (one winner), repeated same-review commit, competing review conflict and 2,000-school atomic assignment. The load operation used 11 SQL statements and about 0.25 seconds locally; this is NOT a hosted Supabase latency claim. The temporary container was removed. No real SMTP.

Frontend lint: zero errors/two existing Fast Refresh warnings. Production build passes with the existing MapLibre chunk warning. Admin/employee/contact/commission/template/ownership demo contracts pass. The local server is still on 127.0.0.1:5173. No rendered desktop/mobile check was completed because the contained Kairos browser previously rejected that localhost port.

Local review in your own browser:
http://127.0.0.1:5173/emails?tab=templates&preview=1&scenario=admin
http://127.0.0.1:5173/schools?view=unassigned&preview=1&scenario=admin

## Release boundary

After local review and separate release authorization: refresh remotes and reconcile any newer Claude Code work. Apply 20261105_contacts.sql, 20261105_shared_templates.sql, then 20261105_school_ownership.sql; verify schema/RLS/grants. Release backend before frontend; explicitly import source templates as an admin. Verify actual production assignments, caps, scheduler settings and new routes before using them. No production import/reassignment/reset or sending has been performed by this work.

Item 4 (contact-based recipient targeting, shared-mailbox deduplication and common reviewed sending safety) has not started. Follow-up cadence and automation modes remain unchanged.


## Subsequent catalog and template-upload extension

David requested team-wide rep attachment selection and generic admin template uploads. See ATTACHMENT_CATALOG.md for current permissions and behavior: catalog metadata/downloads are now available to all signed-in reps, mutations remain admin-only, JSON imports require preview/confirm, and batch-only catalog PDFs supplement immutable template defaults. 256 backend tests and all frontend checks pass. Everything remains local and uncommitted.
