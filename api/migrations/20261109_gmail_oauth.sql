-- Additive authorization storage only. Does not enable a provider or a schedule.
BEGIN;
CREATE TABLE IF NOT EXISTS public.gmail_connections (
    user_id integer PRIMARY KEY REFERENCES public.users(id),
    mailbox varchar(320), refresh_token_cipher text,
    authorized_at timestamp without time zone, revoked_at timestamp without time zone,
    generation integer NOT NULL DEFAULT 0, pending_id varchar(64),
    active boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS public.gmail_authorizations (
    id varchar(64) PRIMARY KEY,
    user_id integer NOT NULL REFERENCES public.users(id),
    generation integer NOT NULL, verifier_cipher text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    consumed_at timestamp without time zone
);
CREATE INDEX IF NOT EXISTS ix_gmail_authorizations_user_id ON public.gmail_authorizations(user_id);
ALTER TABLE public.gmail_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gmail_authorizations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.gmail_connections, public.gmail_authorizations FROM anon, authenticated;
COMMIT;
