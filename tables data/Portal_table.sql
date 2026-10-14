BEGIN;

CREATE EXTENSION IF NOT EXISTS btree_gist;

DO $$
DECLARE
    c RECORD;
    column_names TEXT[];
BEGIN
    FOR c IN
        SELECT con.oid, con.conname, con.conrelid, con.conkey
        FROM pg_constraint con
        JOIN pg_class tbl ON tbl.oid = con.conrelid
        JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
        WHERE ns.nspname = 'public'
          AND tbl.relname = 'deployment_tracker'
          AND con.contype = 'u'
    LOOP
        SELECT array_agg(att.attname ORDER BY key_col.ordinality)
        INTO column_names
        FROM unnest(c.conkey) WITH ORDINALITY AS key_col(attnum, ordinality)
        JOIN pg_attribute att
          ON att.attrelid = c.conrelid
         AND att.attnum = key_col.attnum;

        IF column_names = ARRAY['cr_number']::TEXT[]
           OR column_names = ARRAY['rfid']::TEXT[] THEN
            EXECUTE format(
                'ALTER TABLE public.deployment_tracker DROP CONSTRAINT %I',
                c.conname
            );
        END IF;
    END LOOP;
END $$;


ALTER TABLE public.deployment_tracker
    ADD COLUMN IF NOT EXISTS slot_start TIMESTAMP WITHOUT TIME ZONE,
    ADD COLUMN IF NOT EXISTS slot_end   TIMESTAMP WITHOUT TIME ZONE,
    ADD COLUMN IF NOT EXISTS comments   TEXT;

ALTER TABLE public.deployment_tracker
    DROP CONSTRAINT IF EXISTS deployment_slot_pair_check;
ALTER TABLE public.deployment_tracker
    ADD CONSTRAINT deployment_slot_pair_check
    CHECK (
        (slot_start IS NULL AND slot_end IS NULL)
        OR
        (slot_start IS NOT NULL AND slot_end IS NOT NULL)
    );

ALTER TABLE public.deployment_tracker
    DROP CONSTRAINT IF EXISTS chk_slot_duration;
ALTER TABLE public.deployment_tracker
    ADD CONSTRAINT chk_slot_duration
    CHECK (
        slot_start IS NULL
        OR slot_end = slot_start + INTERVAL '30 minutes'
    );


ALTER TABLE public.deployment_tracker
    DROP CONSTRAINT IF EXISTS deployment_tracker_status_check;
ALTER TABLE public.deployment_tracker
    ADD CONSTRAINT deployment_tracker_status_check
    CHECK (
        status IN (
            'Pending',
            'Scheduled',
            'In Progress',
            'Successful',
            'Failed',
            'Rolled Back',
            'Cancelled',
            'Approved',
            'Rejected'
        )
    );


ALTER TABLE public.deployment_tracker
    DROP CONSTRAINT IF EXISTS no_overlapping_deployment_slots;
ALTER TABLE public.deployment_tracker
    ADD CONSTRAINT no_overlapping_deployment_slots
    EXCLUDE USING gist (
        tsrange(slot_start, slot_end, '[)') WITH &&
    )
    WHERE (
        slot_start IS NOT NULL
        AND slot_end IS NOT NULL
        AND LOWER(TRIM(COALESCE(status, ''))) NOT IN ('cancelled', 'rejected')
    );


CREATE INDEX IF NOT EXISTS idx_deployment_tracker_cr_number_normalized
    ON public.deployment_tracker (LOWER(TRIM(cr_number)));
CREATE INDEX IF NOT EXISTS idx_deployment_date
    ON public.deployment_tracker (deployment_date);
CREATE INDEX IF NOT EXISTS idx_application_name
    ON public.deployment_tracker (application_name);
CREATE INDEX IF NOT EXISTS idx_deployment_status
    ON public.deployment_tracker (status);

COMMIT;
