-- Repair the legacy read/read,write CHECK after optional capabilities were added.
-- Existing keys retain their exact permissions. No keys or approvals are created.
BEGIN;
ALTER TABLE public.agent_api_keys ALTER COLUMN scopes TYPE varchar(255);
ALTER TABLE public.agent_api_keys DROP CONSTRAINT IF EXISTS agent_api_keys_scopes_check;
ALTER TABLE public.agent_api_keys ADD CONSTRAINT agent_api_keys_scopes_check CHECK (
 scopes ~ '^read(,write)?(,(schools:import|outreach:read|outreach:prepare|outreach:send|library:manage|commissions:manage|team:manage))*$'
);
COMMIT;
