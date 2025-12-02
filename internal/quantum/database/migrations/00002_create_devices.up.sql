-- 0002_create_devices.sql

CREATE TABLE IF NOT EXISTS devices (
                                       device_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                       user_id        UUID NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
                                       device_label   VARCHAR(255),
                                       tpm_public_key TEXT NOT NULL,
                                       pq_public_key  TEXT NOT NULL,
                                       created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices (user_id);
