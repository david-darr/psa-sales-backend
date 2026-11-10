# Shared template library: local review

Item 2 implemented locally, 2026-11-05. Item 1 was accepted by David before this work began. Neither item is committed, pushed, migrated on production or deployed. No real emails were sent.

Backend: psa-contacts, feature/contact-foundation. Frontend: react-with-flask/frontend, feature/contact-foundation. Pre-existing agent API edits in psa-due-followups remain untouched.

## Local review

With the existing Vite server running, paste this into your own browser:
http://127.0.0.1:5173/emails?tab=templates&preview=1&scenario=admin

The demo starts with Chris's 16 template texts and fictional recipients. Try search, edit/save a new version, history, archive, restore, and choose a template from Compose or Follow-ups. Library edits affect only this page session. Sending is simulated locally and never contacts Gmail. The contained Kairos browser has previously rejected localhost port 5173, so this implementation has not had a rendered desktop/mobile review.

## Behavior

- Admins create, edit, archive/restore and inspect version history. Reps read active templates and select them for their own outreach. Stable audiences are principal_ap, pta_pto, enrichment, trunk_or_treat and general. Trunk-or-Treat is a campaign audience, not a contact job role.
- Chris's source JSON is api/seed_data/winter_2027_templates.json. An explicit admin import adds missing stable audience/step source keys, never overwrites later changes, and records source provenance/hash. All 16 original subject/body texts are preserved. Nothing seeds production at startup.
- Templates have intro or follow-up 1/2/3 steps. Suggested days 0/4/10/17 are source metadata only. Existing day-3/day-7 sending and automation settings are unchanged. The third template is stored for the later configurable-sequence step, not automatically scheduled now. A follow-up template must match the recipient's next step.
- Supported fields: {school name}, {contact name}, {my name}, {my email}, plus the existing equivalent square aliases. Unknown or malformed fields block; a missing value blocks only when used. Rendered HTML escapes content.
- The composer edits a batch copy. Saved library versions and per-recipient rendered messages are immutable through the API. Queued batches retain their original library snapshot. Archive prevents future selection; it does not change queued or historical mail.
- Shared-template sends require a signed, sender-bound, 15-minute full preview. Changes to copy, recipient merge values, template revision or attachment identity invalidate the proof. Batches using shared templates are capped at 100 recipients to match the existing full-preview capacity. Older non-library send paths retain their current behavior; universal approval enforcement belongs to item 4.
- Source templates default to no attachments. On David's follow-up request, admins can now upload reusable PDFs and select up to THREE per template, including an explicit follow-up attachment. Each file is at most 10 MB and the template total is at most 15 MB. New follow-up templates still start without files. Valid filenames/PDF headers, request/file size limits and private authenticated access are enforced. An admin can also select an existing approved PSA flyer. Assets are content-addressed and copied to private database storage; snapshots bind exact bytes so every later use automatically includes the same selected files. A changed/missing source file cannot alter queued mail. Missing/corrupt stored bytes fail closed. Base64 cache remains bounded and Postgres asset reads release their connection before SMTP.


## API

- GET/POST /api/outreach/templates
- PUT /api/outreach/templates/{id}, with current revision; stale writes return 409.
- GET /api/outreach/templates/{id}/versions, admin only.
- GET/POST /api/outreach/template-assets, admin-only PDF catalogue and reusable uploads; GET /api/outreach/template-assets/{id} is a private admin download.
- POST /api/outreach/templates/seed-winter-2027, admin only, explicit idempotent import.
- Existing /api/email-preview and /api/outreach/batches accept template_id and template_revision plus optional batch-copy subject/body. Template attachment selection comes from its saved version, never the legacy all-flyers boolean.

## Verification

248 backend tests pass across items 1-3, including 18 template tests and 10 ownership tests. Disposable Postgres 17 checks apply the migration twice, verify all three tables' RLS/revoked public grants, concurrent seed idempotence, conflicting edits, immutable history, saved PDF bytes and DB connection release. Frontend lint has no errors and two pre-existing Fast Refresh warnings; production build passes with the existing MapLibre chunk warning. Template, contact, admin, employee and commission demo contracts pass. No live mailbox or hosted deployment tested.

Commands:
python -m pytest api/tests -q --disable-warnings
python -B api/tests/check_templates_postgres.py  # requires explicitly guarded local TEMPLATE_TEST_DATABASE_URL
npm run lint
npm run build
node scripts/check-templates.mjs
node scripts/check-contacts.mjs
node scripts/check-demo.mjs
node scripts/check-demo.mjs --admin
node scripts/check-commissions.mjs

## Rollout boundary

After local acceptance and separate release authorization: recheck current remotes, apply 20261105_contacts.sql then 20261105_shared_templates.sql, verify RLS and grants, release backend then frontend, apply 20261105_school_ownership.sql as well for item 3, and import the 16 templates explicitly as an admin. No campaign enrollment, invitation, new sending schedule or automatic outreach authorization is created. Shared-template files selected in future admin versions must be the actual approved flyer; nothing in this implementation infers one from Chris's source.

Item 3 is now implemented locally; see SCHOOL_OWNERSHIP.md. Nothing is released. Rendered local review remains pending.


## Subsequent catalog and template-upload extension

David requested team-wide rep attachment selection and generic admin template uploads. See ATTACHMENT_CATALOG.md for current permissions and behavior: catalog metadata/downloads are now available to all signed-in reps, mutations remain admin-only, JSON imports require preview/confirm, and batch-only catalog PDFs supplement immutable template defaults. 256 backend tests and all frontend checks pass. Everything remains local and uncommitted.
