-- 1) Add backend_host (nullable initially so we can backfill safely)
ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS backend_host VARCHAR(253);

-- 2) Backfill: default backend_host to domain for existing apps
UPDATE apps
SET backend_host = domain
WHERE backend_host IS NULL;

-- 3) Make it required
ALTER TABLE apps
    ALTER COLUMN backend_host SET NOT NULL;

-- 4) Case-insensitive uniqueness (optional but recommended)
-- If you want to allow multiple apps to share the same backend host, SKIP this.
CREATE UNIQUE INDEX IF NOT EXISTS apps_backend_host_unique_ci
    ON apps (lower(backend_host));

-- 5) Index for common queries (optional)
CREATE INDEX IF NOT EXISTS apps_backend_host_idx
    ON apps (backend_host);