-- Add PQ public key for ML-DSA-65 (1952 bytes)
-- Stored as raw bytes (BYTEA). API/UI uses base64.
-- Nullable for DX: app can be created first, key added later.

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS pq_public_key BYTEA;

ALTER TABLE apps
    ADD CONSTRAINT apps_pq_public_key_len_chk
        CHECK (pq_public_key IS NULL OR octet_length(pq_public_key) = 1952);
