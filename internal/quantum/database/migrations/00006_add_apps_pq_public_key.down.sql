ALTER TABLE apps
    DROP CONSTRAINT IF EXISTS apps_pq_public_key_len_chk;

ALTER TABLE apps
    DROP COLUMN IF EXISTS pq_public_key;
