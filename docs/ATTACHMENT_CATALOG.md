# Shared attachment catalog and admin template uploads

Local implementation, 2026-11-05. David explicitly requested that admins can create/upload templates and PDFs, and reps can independently pick catalog attachments while sending. Nothing committed, pushed, migrated on production, deployed or sent. This extends the unreleased items 1-3 draft in psa-contacts and the frontend feature/contact-foundation branch.

## Roles and workflow

- Outreach / Templates retains admin create/edit/archive/history, batch-copy editing for reps and the 16 original Chris templates.
- Admins can upload a UTF-8 JSON template file: a single template, an array, or an object with a templates array (1 MB / 100 rows maximum). The UI provides a format example. Chris's original audience names and send_on_day values are normalized into the existing audience IDs and step metadata, without changing send timing.
- File preview validates every row and shows create/skip plus attachment names. No library templates are created until the admin explicitly confirms. Reviews are actor-bound, expire in 15 minutes, and repeated/concurrent commits are idempotent. Exact source imports skip existing entries and preserve later admin edits. Invalid files/rows/references block the import without partial writes. Original Chris JSON uses the same stable identities as the built-in import button.
- Outreach / Attachments is a standalone catalog. Admins upload a reusable PDF directly, or explicitly publish one of the existing approved PSA flyers, without creating a template. Every signed-in rep can search/download these team PDFs and select them in the message composer. Upload/publication and template mutation remain admin-only. Anonymous access remains blocked, and direct Supabase public roles retain no access.
- Template-default PDFs are automatically included on every use and cannot be removed by a rep's batch selection. Reps can add separate catalog PDFs for an individual initial, custom or follow-up batch without editing the saved template. A default repeated in the optional selection is deduplicated.
- At most three PDFs and 15 MB combined, including defaults; each uploaded file is at most 10 MB. Filenames/header/type/size restrictions remain enforced. Uploads become intentionally shared team catalog entries; this is not a private file store per rep.
- Selected PDFs require a signed full review (at most 100 recipients for this reviewed flow). Changing PDFs invalidates prior proof. The preview lists final filenames and queued recipients retain immutable file IDs/bytes. Empty explicit catalog selection on a standard intro means no optional flyers, rather than silently attaching every built-in PDF. Older clients that omit the catalog field retain their existing behavior.
- Downloads use authenticated bearer requests and private/no-store responses. The UI downloads a blob, avoiding token-bearing public URLs. File bytes remain immutable and cached with a bounded cache; source replacement cannot alter queued messages.

## API and file shape

GET /api/outreach/template-assets: signed-in catalog metadata, saved assets plus existing approved flyer options.
POST /api/outreach/template-assets: admin multipart file upload.
POST /api/outreach/template-assets/publish: admin JSON {filename}, from the approved local flyer set only.
GET /api/outreach/template-assets/{sha256}: authenticated download for reps/admins.
POST /api/outreach/template-imports/preview: admin multipart JSON file.
POST /api/outreach/template-imports/{review_id}/commit: admin explicit import confirmation.
Existing preview/batch endpoints accept optional attachment_ids for batch-only additional catalog files. Template defaults are resolved server-side and cannot be overridden with that field.

JSON template fields: name, kind (initial/followup), step (0 for intro; 1/2/3 for follow-up), audience (principal_ap/pta_pto/enrichment/trunk_or_treat/general), subject, body, optional attachment_ids from existing catalog. Supported fields in copy remain {school name}, {contact name}, {my name}, {my email}. Use existing asset IDs or choose PDFs after import. Imported files cannot name filesystem paths or upload arbitrary referenced files.

## Verification

256 backend tests pass, including catalog permissions, rep custom sends with PDFs and no template, preview changes, default/optional dedup, size/count limits, independent flyer publication, upload preview/commit/idempotence, invalid rows, actor/expiry checks, and the original Chris JSON import. Disposable Postgres migration tests apply the migration twice and verify all four template/import tables' RLS/public grants, concurrent seed and JSON import dedup, conflicting edits, immutable PDFs and connection release. The temporary container was removed. No real SMTP.

Frontend lint: no errors/two pre-existing Fast Refresh warnings. Production build passes with the existing MapLibre chunk warning. Template/catalog/ownership/contact/admin/employee/commission demo checks pass. The catalog tests run in both admin and employee scenarios with fetch blocked. No rendered browser review was performed; the contained Kairos browser previously rejected localhost port 5173.

Review in your own browser:
http://127.0.0.1:5173/emails?tab=attachments&preview=1&scenario=admin
http://127.0.0.1:5173/emails?tab=templates&preview=1&scenario=admin

## Release boundary

The still-unapplied 20261105_shared_templates.sql now includes mail_template_imports, with RLS and revoked public-role access. The local schema sequence remains contacts, shared templates, then school ownership. No production migration has been applied. Reconcile any newer remote work before a separately authorized release. Sending schedule, automation settings, employee ownership and invitations are unchanged by this catalog extension. Item 4 has not started.
