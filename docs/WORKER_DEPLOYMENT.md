# Proposed PSA sending worker

This is a reviewable hosting proposal, not a provisioned service. Do not merge an API-only release and expect queued mail to send.

## Render proposal

- Service name: `psa-sales-outreach-worker`.
- Service type: Background Worker, in the same workspace/region as the existing backend.
- Repository: `david-darr/psa-sales-backend`; production branch `main`, deployed at the same release revision as the API.
- Build: `pip install -r api/requirements.txt`.
- Start: `python -m api.outreach_worker --poll-seconds 10`.
- Initial size: smallest paid 512 MB instance, subject to confirming availability in the actual workspace. Render's public compute pricing on 2026-11-09 lists this size at $7/month; existing workspace fees, other services and usage are separate. No plan has been selected or purchased.

Reuse the backend's private environment in Render or a private environment group; do not paste credentials in chat or commit an environment file. At minimum the worker needs the same DATABASE_URL, MAIL_CREDENTIAL_KEY, JWT_SECRET_KEY and relevant Google/location integration configuration as the compatible API. Keep MAIL_CREDENTIAL_ALLOW_LEGACY=false and CAMPAIGN_AUTOMATION_ENABLED=false during acceptance. Disable AUTO_FOLLOWUPS_ENABLED on the old web deployment before cutover. The worker disables its own embedded scheduler automatically.

One worker is sufficient for initial controlled acceptance; it takes bounded fair turns across batches. Monitor heartbeat, memory, queue age and sending errors before increasing team load. Scale based on actual hosted measurements rather than local throughput claims. No worker should be started against unreviewed legacy queued work.

## Alternative host

An existing always-on managed host can run the same command if it has private configuration, outbound Gmail SMTP/IMAP access, reliable process restart and logs, and network access to the production database. A laptop that may sleep is unsuitable as the production team worker. A cron-only job needs separate schedule/recovery design and should not be substituted silently.

## Acceptance and activation

Confirm the hosted worker heartbeat first. Authorize a single internal-recipient test separately, verify PDF receipt and reply threading/sync, then test cancellation and hosted recovery without resending uncertain messages. Keep campaign automation off until the employee's bounded campaign can be reviewed and explicitly authorized. A worker can send already-approved manual mail even when campaign automation is false; the queue must be inspected before startup.
