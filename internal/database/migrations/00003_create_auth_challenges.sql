-- 0003_create_auth_challenges.sql

CREATE TABLE IF NOT EXISTS auth_challenges (
                                               challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                               device_id    UUID NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
                                               nonce        STRING       NOT NULL,
                                               expires_at   TIMESTAMPTZ  NOT NULL,
                                               created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_device_id
    ON auth_challenges (device_id);

