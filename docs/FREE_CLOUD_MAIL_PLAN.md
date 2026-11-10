# Cloud-only mail on the existing Free backend

## Confirmed constraints (2026-11-09)

The owner confirmed Render Free, declined an additional paid worker and has no always-on machine available. Keep the existing website deployment unchanged during this work. The preceding environment-only deployment disabled the old automatic sender; it did not release this draft queue code.

Render Free blocks outbound SMTP ports 25/465/587 and sleeps when idle. The opt-in web worker cannot fix those restrictions. Do not enable OUTREACH_WORKER_MODE=web as a solution for this account.

## Candidate architecture, not an activated service

1. Authorize employees with Google OAuth, keeping refresh tokens encrypted and binding each connection to its PSA employee and Google mailbox. App passwords cannot authorize Gmail REST calls.
2. Send MIME messages and read replies through Gmail HTTPS. Preserve the queue's reviewed content, PDF snapshots, recipient reservations, stop checks, caps and uncertain-delivery records. A timeout/5xx after submission must not trigger an implicit resend.
3. Use a bounded authenticated worker invocation, triggered for actual due work by the existing Supabase project's Cron/pg_net support, after verifying project availability and quotas. Keep request duration bounded and use the existing persistent leases. Do not publish a generic unauthenticated send/tick endpoint, expose service-role secrets, or use artificial keep-alive pings.
4. Account for Free-host cold starts, scheduler delays, capacity and service outages in the UI. Do not claim guaranteed on-time delivery or unlimited volume. Validate Supabase quota/egress impact, especially PDF traffic, before enabling a large team.

This avoids proposing another monthly worker subscription, but does not guarantee zero external cost. Gmail reply-reading scopes are restricted. Google Workspace internal-use rules and external-app verification/security assessments differ; establish PSA's account organization before choosing the consent/production rollout. Do not use external OAuth Testing mode as a permanent production connection or bypass required verification.

## Implemented so far

`api/gmail_https.py` is an inactive transport foundation, not a connected production mail provider. Twelve fake-HTTP/real-queue tests cover exact MIME/PDF/thread headers, token refresh boundaries, safe errors, no blind retries, uncertain delivery in the existing ledger, and suppression after review. It is deliberately not selected by the production SMTP factory. No Google credentials have been configured, OAuth accounts connected, cron jobs created or real mail sent.

External-user OAuth onboarding and encrypted connection persistence are now implemented behind a disabled feature flag; see GMAIL_OAUTH_SETUP.md. Eleven focused OAuth tests and local PostgreSQL migration/concurrent-callback checks pass. Connections remain inactive and do not change the existing sender. Bounded HTTPS reply sync, transport activation, native/web controls, the authenticated bounded worker trigger and scheduler installation remain to be implemented and tested. Do not merge/deploy the queue upgrade or publish the Store update based on transport tests alone.

## Other options reviewed

GitHub Actions standard public-repository runners have free usage, but GitHub's terms caution against using Actions as part of a serverless application. Do not turn Actions into PSA's production mail host. No workflow was added or activated.

## Primary references

- https://render.com/docs/free
- https://developers.google.com/workspace/gmail/api/guides/sending
- https://developers.google.com/identity/protocols/oauth2/web-server
- https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification
- https://supabase.com/docs/guides/cron
- https://supabase.com/docs/guides/functions/schedule-functions
- https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features
