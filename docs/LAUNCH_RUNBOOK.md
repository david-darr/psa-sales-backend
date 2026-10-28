# PSA Sales launch runbook (2026-10-29)

Every step that touches production needs David's go-ahead. Nothing here has been pushed, deployed or run against production.

## What changed for launch

- **Sales admin page** (`/admin`, administrators only; reps are redirected and never see the nav item).
  - Ownership: every rep with schools owned, in pipeline, active, former and recent closes, with links to that rep's schools and map.
  - Commissions: a default commission % per rep, "Record a close" (stage, deal value, close date, closer) and an optional split across reps with per-rep rate overrides. Shares must total 100%. With no split, the closer earns 100% at their default rate. Report by this month, last month, this year or all time, with CSV export and a "needs review" filter for closes missing a deal value or rate.
  - Reps can still move their own school to Active client; that close shows up under "Needs review" until an administrator adds the deal value.
- **Team sign-up link**: Team > Invite teammate (or Settings > Admin) > Team sign-up link. One link for the whole team, expiring after 1, 7, 14 or 30 days, with a sign-up limit, and a Turn off button. Accounts created this way are never administrators. Per-email invitations still work.
- **Sign-up and sign-in**: passwords need 8+ characters, emails are matched case-insensitively, a new rep is signed in straight after creating an account, and a wrong password now says so instead of "session expired".
- **New rep checklist** on Overview: connect Gmail, add or claim schools, send a first intro, plan a task. It disappears once done.

Backend: `api/admin_sales.py`, `api/api.py` (models, register, login), migration `api/migrations/20261029_launch_admin.sql`, reset `api/maintenance/20261029_launch_reset.sql`, tests `api/tests/test_admin_sales.py`.
Frontend: `src/SalesAdmin.jsx`, `src/components/JoinLinks.jsx`, `src/lib/preview/admin.js`, plus edits to `App.jsx`, `NavigationCard.jsx`, `Account.jsx`, `Team.jsx`, `Home.jsx`, `lib/api.js`, `styles/platform.css`.

## Verified locally

- Backend: 143 tests pass (`python -m pytest api/tests -q --disable-warnings`), including 8 new ones for commissions, closes, join links and login.
- Load: `api/tests/load_outreach.py` 49/49 against a throwaway Postgres, including 30 reps sending at once (web p95 44 ms, no duplicate emails).
- Migration applied twice to a throwaway Postgres without errors. Reset run on seeded data: only administrators remain, the geocode cache is kept, and it refuses to run if no administrator exists.
- Frontend: lint (0 errors), build, employee and admin demo checks. In the browser: Sales admin ownership and commissions, a 50/50 split at 12% and 7% on $10,000 showing $600 and $350, reps redirected away from `/admin`, and a full join-link sign-up against the local backend landing on the checklist.

Not verified: production deploy, a real Gmail send after the reset.

## Release order

1. **Back up** the Supabase database (Dashboard > Database > Backups, or `pg_dump`).
2. **Apply** `api/migrations/20261029_launch_admin.sql` (additive, safe to rerun).
3. **Deploy backend** (push to `main` of the backend repo; Render deploys). Check `/api/join-links/check` answers `{"valid": false}` for a dummy token.
4. **Deploy frontend** (push to `main`; Vercel deploys).
5. **Confirm who stays admin.** The reset keeps only accounts with `admin = true`. Today that is David Darr and Christopher Garabito. Grant admin on the Team page first to anyone else who must keep their login (for example Ricky), or they will need to sign up again.
6. **Run the reset** `api/maintenance/20261029_launch_reset.sql` in the SQL editor. Read the preview query at the top first. It deletes every school, email, reply, thread, task, activity, outreach batch, map snapshot, invitation, join link and non-admin account.
7. **Import the new school list**: Outreach > Add tab > upload CSV (columns `school_name`, `email`, optional `contact_name`, `phone`, `address`, `school_type`). Uploaded schools belong to the uploader; use Schools bulk select > Assign owner to hand them to reps once they have joined.
8. **Create a sign-up link** and post it to the team.
9. **Smoke test** with one rep account: sign up, connect Gmail, one single-recipient send to an internal address, record a test close in Sales admin, then delete the test data.

## Rep instructions (paste into the team chat)

> Welcome to PSA Sales: salespsa.com
> 1. Open the sign-up link below and create your account with your work email (password 8+ characters).
> 2. On Overview, follow "Get set up": connect Gmail with a Google App Password (Settings > Email connection walks you through it), then claim your schools.
> 3. Send your first intro from Outreach and add next steps as tasks.
> Questions: ask David or Christopher.
