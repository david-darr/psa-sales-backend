-- Personal API keys for AI assistants and integrations (api/agent_api.py).
-- Apply after the 20261029 migrations. Additive and safe to run again.
--   * agent_api_keys: SHA-256 hashes only; the full key is shown once and never stored.
--   * agent_api_audit: key, employee, method, route template and status. No request
--     or response content. Also backs the 60 requests/minute per-key rate limit.
BEGIN;

CREATE TABLE IF NOT EXISTS agent_api_keys (
    id serial PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name varchar(80) NOT NULL,
    key_hash varchar(64) NOT NULL UNIQUE,
    key_hint varchar(20) NOT NULL,
    scopes varchar(40) NOT NULL DEFAULT 'read'
        CHECK (scopes IN ('read', 'read,write')),
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    expires_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    last_used_at timestamp without time zone
);
CREATE INDEX IF NOT EXISTS ix_agent_api_keys_user_id ON agent_api_keys(user_id);

CREATE TABLE IF NOT EXISTS agent_api_audit (
    id bigserial PRIMARY KEY,
    key_id integer NOT NULL REFERENCES agent_api_keys(id) ON DELETE CASCADE,
    user_id integer NOT NULL,
    method varchar(8) NOT NULL,
    route varchar(120) NOT NULL,
    status integer NOT NULL,
    created_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS ix_agent_api_audit_key_time ON agent_api_audit(key_id, created_at);

-- Only the Flask backend (database owner) reads these tables; Supabase's public
-- roles get no access even if the Data API is enabled.
ALTER TABLE agent_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_api_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE agent_api_keys FROM anon, authenticated;
REVOKE ALL ON TABLE agent_api_audit FROM anon, authenticated;
REVOKE ALL ON SEQUENCE agent_api_keys_id_seq FROM anon, authenticated;
REVOKE ALL ON SEQUENCE agent_api_audit_id_seq FROM anon, authenticated;

COMMIT;
