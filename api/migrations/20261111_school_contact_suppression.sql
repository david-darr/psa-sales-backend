-- Additive; existing global opt-outs remain unchanged. Apply before release.
BEGIN;
ALTER TABLE public.school_contacts ADD COLUMN IF NOT EXISTS do_not_contact boolean NOT NULL DEFAULT false;
ALTER TABLE public.school_contacts ADD COLUMN IF NOT EXISTS suppression_reason text NOT NULL DEFAULT '';
COMMIT;
