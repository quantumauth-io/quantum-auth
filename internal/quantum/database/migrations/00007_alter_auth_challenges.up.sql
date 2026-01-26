
ALTER TABLE auth_challenges
    ADD COLUMN IF NOT EXISTS app_id UUID;

DELETE FROM auth_challenges
WHERE app_id IS NULL;

DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'auth_challenges_app_id_fkey'
        ) THEN
            ALTER TABLE auth_challenges
                ADD CONSTRAINT auth_challenges_app_id_fkey
                    FOREIGN KEY (app_id) REFERENCES apps (app_id) ON DELETE CASCADE;
        END IF;
    END $$;

ALTER TABLE auth_challenges
    ALTER COLUMN app_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_challenges_device_app
    ON auth_challenges (device_id, app_id);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at
    ON auth_challenges (expires_at);