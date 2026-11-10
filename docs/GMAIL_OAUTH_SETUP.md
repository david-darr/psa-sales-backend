# Gmail HTTPS authorization: local implementation and setup

## Assumption

No answer was received about PSA's Google organization. Assume personal Gmail or mixed organizations and design for External Google OAuth users. This is not confirmation that PSA meets an internal-use verification exemption. Do not purchase hosting, start a live scheduler or authorize a campaign from this assumption.

## Implemented

The authorization endpoints are disabled by default (`GMAIL_OAUTH_ENABLED=false`). They require private employee JWTs for start, status and disconnect; an agent API key cannot authorize a Google account for an employee. The callback uses a random expiring one-use state, PKCE and exact employee-mailbox verification. Refresh tokens and PKCE verifiers are encrypted using the existing persistent `MAIL_CREDENTIAL_KEY`. Google access tokens are transient. Disconnect invalidates outstanding connection links and defeats a callback completing later.

A successful authorization is `authorized_pending_activation`. It never replaces the existing app password, enables HTTPS sending, changes a quota, grants an agent permission or enables an approved campaign. There is deliberately no activation endpoint yet. Do not set connection.active manually.

Routes:

- POST `/api/mail/google/connect`: private employee JWT; returns the Google consent URL, valid for ten minutes. The human completes Google consent.
- GET `/api/mail/google/callback`: fixed registered callback; consumes the state once and verifies the returned Gmail profile and both scopes.
- GET `/api/mail/google/status`: employee-scoped status, no secrets.
- POST `/api/mail/google/disconnect`: removes local authorization and invalidates pending flows. It does not claim to revoke Google's grant remotely; the employee can remove PSA access in Google Account security settings.

The tables come from `20261109_gmail_oauth.sql`, an eighth additive release migration after the seven existing draft migrations. It was tested on disposable local PostgreSQL, including RLS and revoked public-role table access. It has not been applied to production.

## Human setup, only when the remaining HTTPS mail implementation is ready

1. Use a PSA-controlled Google Cloud project and enable the Gmail API. Configure an External OAuth consent screen unless an actual organization-owned internal setup is confirmed.
2. Supply the production home page, privacy policy, verified domain, administrator contact and the required Gmail scopes: `https://www.googleapis.com/auth/gmail.send` and `https://www.googleapis.com/auth/gmail.readonly`.
3. Review Google's current verification and security-assessment requirements before production rollout. Restricted read scopes can introduce assessment obligations/costs. External Testing mode is not a permanent production solution: authorization refresh tokens can expire after seven days. Do not promise that this architecture guarantees zero external cost.
4. Create a Web application OAuth client with the exact backend callback URL, for example `https://psa-sales-backend.onrender.com/api/mail/google/callback`. The callback comes from server configuration, never a browser-supplied host or return URL.
5. Save `GMAIL_OAUTH_CLIENT_ID`, `GMAIL_OAUTH_CLIENT_SECRET` and `GMAIL_OAUTH_REDIRECT_URI` privately in Render. Keep `MAIL_CREDENTIAL_KEY` unchanged. Never paste secrets, codes or refresh tokens into chat, commit them or put them in a downloadable file.
6. Apply the additive migration before enabling `GMAIL_OAUTH_ENABLED`. Keep it false for now: the sender switch, HTTPS reply sync, private native/web controls and scheduler acceptance are unfinished.

## Remaining integration

- Bounded Gmail HTTPS reply sync with durable paging and freshness/stop safeguards.
- Explicit, reversible transport activation and all existing mailbox-eligibility paths.
- Private web/native connection controls; chat tools must not receive passwords or authorization tokens.
- Authenticated bounded queue invocation and actual-work scheduling via Supabase, with host cold-start, timeout and capacity tests.
- Google production verification/account authorization, then separately approved internal-recipient acceptance tests.

No paid service, real Google connection, cron job or production send was created by this development.

References: https://developers.google.com/identity/protocols/oauth2/web-server and https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification

## Verification record

Latest complete backend run: 380 passed. Eleven focused OAuth tests pass. Disposable PostgreSQL verified the migration twice, RLS/public grants and concurrent callback consumption. One pre-existing school-audit import test failed during the first full run, then passed in isolation and the subsequent full run; the cause was not isolated, so retain this as a non-reproduced test-isolation concern. No frontend or native UI changes were made in this authorization step.
