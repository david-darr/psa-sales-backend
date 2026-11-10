-- Credential hash only. Does not create or activate the cloud schedule.
BEGIN;
CREATE TABLE IF NOT EXISTS public.outreach_clock_credentials (
 id integer PRIMARY KEY CHECK(id=1), token_hash varchar(64) NOT NULL,
 last_wake_at timestamp without time zone
);
ALTER TABLE public.outreach_clock_credentials ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.outreach_clock_credentials FROM anon,authenticated;
COMMIT;
