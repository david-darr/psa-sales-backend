-- Run only after migrations and the compatible API are verified.
-- Installs DISABLED. No credential is printed or passed through the client.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
DO $$
DECLARE token text;
BEGIN
 SELECT decrypted_secret INTO token FROM vault.decrypted_secrets WHERE name='psa_outreach_clock';
 IF token IS NULL THEN
  token:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
  PERFORM vault.create_secret(token,'psa_outreach_clock','Narrow PSA queue wake credential; no approval or data access');
 END IF;
 INSERT INTO public.outreach_clock_credentials(id,token_hash)
 VALUES (1,encode(sha256(convert_to(token,'UTF8')),'hex'))
 ON CONFLICT(id) DO UPDATE SET token_hash=EXCLUDED.token_hash;
END $$;

CREATE OR REPLACE FUNCTION public.psa_outreach_clock() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE token text; request_id bigint;
BEGIN
 -- Trigger real work, not a keep-alive: idle projects produce no HTTP request.
 IF NOT (
  EXISTS(SELECT 1 FROM public.outreach_batches WHERE
   (status='queued' AND (available_at IS NULL OR available_at<=now() AT TIME ZONE 'UTC'))
   OR (status='sending' AND lease_until<now() AT TIME ZONE 'UTC'))
  OR EXISTS(SELECT 1 FROM public.mail_sequence_steps s JOIN public.mail_sequence_enrollments e ON e.id=s.enrollment_id
   WHERE e.status='active' AND (s.status='queued' OR
    (s.status='waiting' AND (e.mode='automatic' OR s.approved_until>now() AT TIME ZONE 'UTC') AND s.due_at<=now() AT TIME ZONE 'UTC')))
  OR EXISTS(SELECT 1 FROM public.approved_campaign_plans WHERE status IN ('scheduled','running'))
  OR EXISTS(SELECT 1 FROM public.users u LEFT JOIN public.mail_sync_states m ON m.user_id=u.id
   WHERE coalesce(u.email_password,'')<>'' AND EXISTS(
    SELECT 1 FROM public.sent_emails e WHERE e.user_id=u.id AND e.sent_at>=now() AT TIME ZONE 'UTC'-interval '90 days')
   AND (m.last_checked_at IS NULL OR m.last_checked_at<=now() AT TIME ZONE 'UTC'-interval '30 minutes'
    OR (m.pending_count>0 AND m.last_error IS NULL)))
 ) THEN RETURN NULL; END IF;
 SELECT decrypted_secret INTO token FROM vault.decrypted_secrets WHERE name='psa_outreach_clock';
 IF token IS NULL THEN RAISE EXCEPTION 'PSA queue wake credential missing'; END IF;
 SELECT net.http_post(
  url:='https://psa-sales-backend.onrender.com/api/internal/outreach/wake',
  headers:=jsonb_build_object('Content-Type','application/json','Authorization','Bearer '||token),
  body:='{"source":"supabase_cron"}'::jsonb,timeout_milliseconds:=60000
 ) INTO request_id;
 RETURN request_id;
END $$;
REVOKE ALL ON FUNCTION public.psa_outreach_clock() FROM PUBLIC,anon,authenticated;
SELECT cron.schedule('psa-outreach-clock','*/5 * * * *','SELECT public.psa_outreach_clock();');
SELECT cron.alter_job(jobid,active:=false) FROM cron.job WHERE jobname='psa-outreach-clock';
COMMIT;
