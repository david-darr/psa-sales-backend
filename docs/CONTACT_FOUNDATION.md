# Contact foundation and reviewed imports

Item 1 of the campaign automation plan, implemented locally on 2026-11-05. Not committed, pushed, migrated on production or deployed. David accepted the local UI before item 2 began.

Backend worktree: `C:\Users\David\Documents\Random Coding Projects\psa test\psa-contacts`, branch `feature/contact-foundation`, based on `8e77355`. Frontend: `react-with-flask/frontend`, branch `feature/contact-foundation`, based on `2691edf`. The pre-existing agent API edits in `psa-due-followups` were left untouched.

## Behavior

- `contacts` stores one normalized mailbox identity, do-not-contact, suppression reason and version. Normalization trims/lowercases only; it does not strip Gmail dots or plus aliases.
- `school_contacts` links identities to schools, with per-school contact name, roles, audience tags, primary flag and version. The same PTA mailbox may belong to multiple schools. Other reps cannot see names/links of schools outside their permitted scope; a shared count is shown.
- Roles are `unknown`, `principal_ap`, `pta_pto`, `enrichment`, and `other_staff`. Trunk-or-Treat is an audience/history tag, not a role.
- County is optional school metadata. It is editable on the school detail form. County-based bulk assignment belongs to the later ownership step.
- New contacts/updates project into the existing primary/additional-email fields. Legacy ORM writes also synchronize contact links. Name/role/suppression data is preserved; removing an address from legacy fields unlinks it but retains its mailbox identity and global suppression.
- Adding/importing contacts does not expand recipient targeting or change follow-up scheduling. The current batch still picks its existing single recipient. New DNC flags are enforced by recipient eligibility, worker rechecks, and both SMTP entry points. Contact opt-out cannot be bypassed by switching the contact's school association. Only an admin may clear DNC, with a reason. School-level suppressions are retained.
- Contact changes carry optimistic versions; import/contact writes are serialized by a transaction-held guard row. A stale editor cannot overwrite another user's changes. School access is rechecked under a row lock before writing.
- Email alone is not proof of school identity. Manual/Finder adds still warn about an existing shared mailbox; a manual distinct-school confirmation bypasses only the email warning, never name/address checks. Name/address variants remain review candidates. New CSV imports link shared identities rather than merge schools by email.

## API and import flow

`GET/POST /api/sales-schools/{id}/contacts` lists or adds contacts. `PATCH /api/sales-schools/{id}/contacts/{link_id}` edits name, roles, tags, primary and suppression with both link and contact versions. Identity email is immutable; add a new association for a new mailbox. Current owners/admins may use these routes.

`POST /api/contact-imports/preview` takes multipart `file`, UTF-8 CSV (BOM accepted), maximum 2 MB / 2,000 rows. Required columns: `school_name,email`. Optional: `contact_name,contact_role,address,county,school_type,stage,notes,phone,audience_tags,do_not_contact,suppression_reason`. Common legacy header aliases remain accepted; unrecognized or duplicate headers are rejected to avoid silently losing new data. Role aliases such as principal, PTA and ASEP are accepted; multiple roles/tags use semicolons or pipes.

The preview persists a 30-minute, actor-bound review record with file SHA-256, parsed rows and a school/contact snapshot. It writes no school/contact records. School groups show new/existing/conflict outcomes; contact rows identify add, existing, shared or repeated contacts and retained suppression. Invalid rows are listed individually. Users resolve candidates by adding contacts to an authorized existing match, explicitly creating a distinct school, skipping the group, or correcting the CSV. An exact existing school cannot be forced into a duplicate new record.

`POST /api/contact-imports/{id}/commit` supplies `file_hash`, optional group-keyed `decisions`, and `skip_invalid=true` only after the person reviews and elects to skip invalid rows. It rechecks current access and the snapshot; changes require a new preview. New schools belong to the authenticated importer and default to pending unless an explicit valid stage was supplied. Existing owners, stages and notes are not overwritten. Empty county can be filled. Existing contact role/tag sets are enriched and nonblank names retained; imports never clear DNC. A repeated commit returns its saved result; simultaneous competing previews cannot both create the same school/contact set.

Records and audit events are committed together. There is no real email send in this flow. New account invitations, templates, audience-targeted batch sends, new follow-up schedules, campaign approvals and reporting are not implemented in this step.

## Verification

- Backend suite: 220 passed, including 12 contact/import tests. After moving the Finder lock to the save path, the relevant Finder/contact/outreach regression set passed again (84 tests).
- Disposable PostgreSQL 17: migration applied twice; malformed legacy JSON skipped safely; shared contacts backfilled; prior opt-outs carried forward; RLS and public-role grants verified; simultaneous same-preview commits returned one saved result; competing previews produced one success and one stale-review conflict. Deleting a school preserved the mailbox opt-out and audit while removing its associations.
- Synthetic 145-school/410-contact commit: about 0.5 seconds and 591 statements on local Postgres. This is not a measurement of Render/Supabase latency. The import uses prefetched canonical rows and batched writes rather than one network lookup per contact.
- Frontend lint: no errors, two existing Fast Refresh warnings. Production build passed, with the existing MapLibre chunk-size warning. Contact, commission, employee and admin demo checks passed. `scripts/check-contacts.mjs` checks roles, DNC, stale edits, CSV dry run, multi-contact commit and idempotence without HTTP calls.
- Browser rendering could not be verified: Kairos's contained-browser egress policy rejected port 5173. No alternate route was used to bypass that policy.
- No live mailbox, customer CSV or production database was used. The disposable test database was removed after verification.

## Local review

Vite is running on loopback only. Paste into your own browser:

`http://127.0.0.1:5173/schools/1?preview=1&scenario=admin`

Review Contacts and roles, add/edit a fictional contact, set DNC with a reason, and edit county in school details. For imports, open `/emails?tab=add&preview=1&scenario=admin`, choose Upload CSV File, download the sample, preview it and inspect the explicit confirmation step. Demo actions remain fictional and email sending is disabled. Demo behavior is a UI contract exercise; backend/Postgres tests validate server behavior separately.

## Before any release

Review and apply `api/migrations/20261105_contacts.sql` before deploying this backend. It is additive and rerunnable, requires PostgreSQL 16+, keeps legacy fields, backfills valid main/additional addresses with unknown roles and preserves existing opt-outs. It enables RLS and revokes anon/authenticated table and sequence privileges for all five new tables. Review counts for invalid legacy email/JSON before rollout; the migration deliberately does not guess invalid values.

Then deploy backend before frontend and perform authenticated acceptance with an authorized employee/admin and a reviewed small CSV. No new secrets or dependencies are required. Do not release the next template/campaign step as part of this migration. Keep the existing mailbox encryption key and follow-up configuration unchanged.
