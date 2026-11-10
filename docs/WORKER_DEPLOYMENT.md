# PSA sending worker hosting

> Superseded for tonight by [RELEASE_20261110.md](RELEASE_20261110.md): the deployed process was measured to reach SMTP/IMAP successfully. Reuse existing compute and credentials; OAuth remains disabled. Earlier hosting assumptions below are historical, not the active cutover plan.

> Current hosting decision: the existing backend is Render Free, no paid worker is authorized, and no always-on machine is available. Cutover is blocked until a cloud-compatible transport and scheduler are ready. See [FREE_CLOUD_MAIL_PLAN.md](FREE_CLOUD_MAIL_PLAN.md). Web mode does not bypass the SMTP restriction.

No additional paid service is authorized or required by the application. Hosting must still support outbound Gmail SMTP and the desired scheduling availability.

## Reuse the existing backend

The compatible backend can run the same durable queue with `OUTREACH_WORKER_MODE=web` and `OUTREACH_POLL_SECONDS=10`. Default mode is `external`, preserving the existing dedicated-worker deployment option. Configure web mode only with the compatible release, after its migrations and queue inspection.

The first request starts one background thread per web process, without doing SMTP in the request. Database leases coordinate concurrent workers. Saved approvals, caps, cancellation, recipient reservations and uncertain-send handling remain enforced. Each turn processes one bounded batch job. Restarting resumes eligible saved work; it does not blindly resend uncertain mail. Monitor memory, heartbeat and API latency on the actual host.

This reuses existing compute, rather than provisioning another service. It does not keep a sleeping host awake. Scheduled messages wait while the host is asleep or unavailable. Render Free sleeps after 15 minutes without inbound traffic and blocks outbound SMTP ports 25, 465 and 587; web mode cannot bypass those limits. Confirm the existing service plan before enabling production sending. If the backend is already paid, this mode adds no separate worker service. If it is Free, pause cutover until an authorized SMTP-capable existing host or a reviewed HTTPS mail transport is available. Do not promise free always-on automation.

Reference: https://render.com/docs/free

## Existing external host option

An already available always-on host can run `python -m api.outreach_worker --poll-seconds 10` at the compatible API revision, with `OUTREACH_WORKER_MODE=external`. It needs private database/mail configuration, outbound SMTP/IMAP, process restart and logs. No new paid host is provisioned by this proposal.

## Acceptance and activation

Keep `AUTO_FOLLOWUPS_ENABLED=false`, `MAIL_CREDENTIAL_ALLOW_LEGACY=false` and `CAMPAIGN_AUTOMATION_ENABLED=false`. Keep the existing persistent `MAIL_CREDENTIAL_KEY` unchanged. Inspect pending work before starting either worker mode. Confirm heartbeat and permissions, then perform a separately authorized single internal-recipient test, PDF receipt, reply sync, cancellation and restart recovery. Campaign automation stays off until explicitly approved. Both modes can send already-approved manual mail even with campaign automation off.
