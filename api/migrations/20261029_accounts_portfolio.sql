-- Apply AFTER 20261028_sales_workspace.sql, before this release.
-- Additive and safe to run again.
--   * closed-won tracking: closed_at / closed_by_id (set by the app the first time a
--     school becomes a client; 'former' = was a client, no longer active)
--   * finder/map data: place_id, lat, lng, website
BEGIN;

ALTER TABLE sales_schools
    ADD COLUMN IF NOT EXISTS closed_at timestamp with time zone,
    ADD COLUMN IF NOT EXISTS closed_by_id integer REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS place_id text,
    ADD COLUMN IF NOT EXISTS lat double precision,
    ADD COLUMN IF NOT EXISTS lng double precision,
    ADD COLUMN IF NOT EXISTS website text;

CREATE INDEX IF NOT EXISTS ix_sales_schools_place_id ON sales_schools(place_id);
CREATE INDEX IF NOT EXISTS ix_sales_schools_closed_at ON sales_schools(closed_at DESC);
CREATE INDEX IF NOT EXISTS ix_sales_schools_closed_by ON sales_schools(closed_by_id);

-- If an older status CHECK constraint exists it would reject the new 'former' stage.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'sales_schools_status_check'
                 AND conrelid = 'sales_schools'::regclass) THEN
        ALTER TABLE sales_schools DROP CONSTRAINT sales_schools_status_check;
        ALTER TABLE sales_schools ADD CONSTRAINT sales_schools_status_check
            CHECK (status IS NULL OR status IN
                ('pending', 'contacted', 'replied', 'meeting', 'partner', 'former', 'not_interested'))
            NOT VALID;
    END IF;
END $$;

-- Backfill: existing clients get a close date (updated_at when the table has that
-- column, otherwise created_at, otherwise now) and the owning rep as the closer.
DO $$
DECLARE
    stamp text := 'now()';
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'sales_schools' AND column_name = 'created_at') THEN
        stamp := '(created_at AT TIME ZONE ''UTC'')';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'sales_schools' AND column_name = 'updated_at') THEN
        stamp := '(updated_at AT TIME ZONE ''UTC'')';
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = current_schema()
                     AND table_name = 'sales_schools' AND column_name = 'created_at') THEN
            stamp := 'COALESCE(updated_at AT TIME ZONE ''UTC'', created_at AT TIME ZONE ''UTC'', now())';
        END IF;
    ELSIF stamp <> 'now()' THEN
        stamp := 'COALESCE(' || stamp || ', now())';
    END IF;
    EXECUTE 'UPDATE sales_schools SET closed_at = ' || stamp
         || ', closed_by_id = COALESCE(closed_by_id, user_id)'
         || ' WHERE status IN (''partner'', ''former'') AND closed_at IS NULL';
END $$;

COMMIT;
