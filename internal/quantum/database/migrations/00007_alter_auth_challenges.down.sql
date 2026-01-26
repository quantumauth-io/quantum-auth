DROP INDEX IF EXISTS idx_auth_challenges_expires_at;
DROP INDEX IF EXISTS idx_auth_challenges_device_app;

ALTER TABLE auth_challenges
    DROP CONSTRAINT IF EXISTS auth_challenges_app_id_fkey;

ALTER TABLE auth_challenges
    DROP COLUMN IF EXISTS app_id;