# Chat operation coverage (local draft)

PSA Command is usable from any Kairos chat where the person has selected its connection. It is not restricted to the chat embedded in the tab. The connection is not silently enabled for every existing chat.

The API uses the connected employee identity and current role. All new administration capabilities are opt-in. No migration is added by this change; the earlier contacts, templates, worker and campaign migrations remain prerequisites for that unreleased draft.

## Operation coverage

| Tool | Permission and behavior |
| --- | --- |
| `psa_directory` | Search the school directory before creating leads. Does not send email. Requires read. |
| `psa_profile` | Read your name, phone and mailbox connection status. Never returns mail credentials. Requires read. |
| `psa_edit_profile` | Update only the connected employee name or phone. Account credentials remain private. Requires write. |
| `psa_bulk_school_stage` | Change the stage of up to 100 accessible schools atomically. Review names and current stages first. Requires write. |
| `psa_create_school` | Add a school with duplicate protection. Use contact import for multi-contact lists. Requires write. |
| `psa_edit_school` | Edit school details, stage, county, notes or next action using normal school access rules. Requires write. |
| `psa_delete_schools` | Permanently delete selected owned schools. Review IDs and names first. Sent history is retained. Requires write. |
| `psa_add_contact` | Add a role-based school contact. Shared mailbox suppression remains global. Requires write. |
| `psa_edit_contact` | Edit a linked contact using current link and contact versions. Only admins may lift suppression. Requires write. |
| `psa_report_contact` | Record an opt-out, complaint or review signal and pause affected outreach. Explain the source. Requires write. |
| `psa_assignment_preview` | Admin: preview moving matching schools to a rep or the unassigned pool. Never changes owners. Requires write. |
| `psa_assignment_commit` | Admin: apply a reviewed, unexpired school assignment. Changed selections require a new preview. Requires write. |
| `psa_claim_school` | Claim one unassigned school for the connected employee. Competing claims return a conflict. Requires write. |
| `psa_find_schools` | Find nearby schools using address or coordinates, keywords and radius. May call the location provider. Requires read. |
| `psa_place_details` | Read contact details for a discovered place ID. Requires read. |
| `psa_save_discovered_schools` | Save selected discovered schools with duplicate checks. Reps can assign only to themselves. Requires write. |
| `psa_map_accounts` | Read owned school coordinates, stages and rep colors for territory planning. Requires read. |
| `psa_locate_schools` | Resolve missing coordinates in a bounded pass using the existing location cache. Requires write. |
| `psa_map_layers` | Read saved PSA, partner and elementary prospect map layers. Requires read. |
| `psa_refresh_map_layers` | Admin: refresh saved prospect map layers from their configured source. Requires write. |
| `psa_plan_visits` | Suggest a bounded visit order from a starting address and selected coordinates. Not driving directions. Requires read. |
| `psa_template_versions` | Read saved text and PDF revision history for a shared template. Requires outreach:read. |
| `psa_create_template` | Admin: create a shared email template with reusable catalog PDF IDs. Does not send mail. Requires library:manage. |
| `psa_edit_template` | Admin: edit or archive a shared template with its current revision; queued copy stays frozen. Requires library:manage. |
| `psa_seed_templates` | Admin: add missing Winter 2027 templates without replacing later edits. Requires library:manage. |
| `psa_publish_pdf` | Admin: copy an approved built-in PSA PDF into the reusable catalog. Requires library:manage. |
| `psa_upload_pdf` | Admin: upload a chosen PDF to the reusable catalog. Supply filename and base64 bytes; maximum 10 MB decoded. Never sends mail. Requires library:manage. |
| `psa_upload_templates` | Admin: upload template JSON for a review preview. Review then commit; existing edits are preserved. Requires library:manage. |
| `psa_commit_template_import` | Admin: commit a reviewed template JSON import by its returned review ID. Stale reviews are rejected. Requires library:manage. |
| `psa_create_sequence` | Admin: create a versioned follow-up definition; does not enroll or send to contacts. Requires library:manage. |
| `psa_edit_sequence` | Admin: edit or archive a follow-up definition using its revision. Changes stop existing enrollments so they need a new review. Requires library:manage. |
| `psa_sequence_versions` | Read follow-up definition revisions. Requires outreach:read. |
| `psa_sequence_originals` | Read eligible original messages before preparing a follow-up plan. No enrollment or sending. Requires outreach:read. |
| `psa_mail_limits` | Read the connected employee daily sending allowance. Requires outreach:read. |
| `psa_outreach_campaigns` | Read outreach campaign IDs and their current daily caps. Does not authorize sending. Requires outreach:read. |
| `psa_create_outreach_campaign` | Admin: create a distinct outreach campaign label and cap with a reason. Does not approve recipients or start sending. Requires library:manage. |
| `psa_worker_status` | Read sending worker freshness and queue status. Requires outreach:read. |
| `psa_program_commissions` | Admin: read seasonal commission records and rep/season totals. Requires read. |
| `psa_create_commission` | Admin: record one school/program/season commission with explicit rep payout. Requires commissions:manage. |
| `psa_edit_commission` | Admin: correct or void a commission using the current revision; history is preserved. Requires commissions:manage. |
| `psa_commission_history` | Admin: read correction history for a seasonal commission. Requires read. |
| `psa_set_team_access` | Admin: change a teammate admin role; normal self/last-admin protections remain. Requires team:manage. |
| `psa_join_links` | Admin: list employee join-link metadata. Requires read. |
| `psa_create_join_link` | Admin: create an employee join link with explicit expiry and use limit. Treat the returned invite token as private. Requires team:manage. |
| `psa_revoke_join_link` | Admin: revoke one employee join link. Requires team:manage. |
| `psa_capabilities` | Check operation availability, delegated permissions and human-only controls for this connection. |
| `psa_prepare_reply` | Prepare a threaded reply for private human review. Requires outreach:prepare. Never approves or sends; execute the approved draft with psa_execute_approved_outreach. |

Existing tools also cover pipeline/team/account reporting, school searches and timelines, sales and Taskbar tasks, imports, recipient targeting, campaign preparation/summaries/stop, replies, follow-up status and execution of already approved sends.

## Human controls and connection setup

1. Release the compatible PSA backend before using these new routes against production.
2. In Kairos Tool Store > Tabs > Yours, review and approve the changed PSA Command source. Restart Kairos to load changed Python code if it was already mounted.
3. In Tool Store > Tools, check PSA Command and review its held new/changed tool definitions. This source update does not accept tools automatically.
4. In each existing or new chat, select PSA Command in Integrations. Ask for `psa_capabilities` to see actual server availability and delegated access.
5. To manage libraries, commissions or team access, an admin creates a new explicitly scoped key. Existing keys are unchanged. Never paste keys/passwords into chat.

Final campaign, message and follow-up approvals remain private human controls in the existing tab. Account sign-in, mail app passwords and API-key delegation are also human-only. The model cannot approve itself or reuse the human JWT. Approvals are not completed solely by a model-supplied confirm flag.

Chosen files can be uploaded without placing their base64 in chat history using the local CLI: `node integrations/psa-cli.mjs psa_upload_pdf --file <chosen.pdf>` or `psa_upload_templates --file <chosen.json>`, with API credentials supplied through private environment configuration. MCP callers can provide bounded file bytes directly. PDF limit is 10 MB decoded; template JSON is 1 MB.

## Local verification

Backend tests exercise permission boundaries, revoked keys, role demotion, stale revisions, import/assignment review, PDF upload and frozen threaded replies. Native bridge tests use fresh independent connection maps and the source-only archive. No live Gmail or production records are used.

The phone renderer is an isolated 390px fixture, not the mounted Kairos shell. Its main selector was keyboard-tested; the computer safety checker blocked the outreach selector as a social action, so that interaction needs human review.
