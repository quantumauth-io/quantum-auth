DROP INDEX IF EXISTS apps_backend_host_idx;
DROP INDEX IF EXISTS apps_backend_host_unique_ci;

ALTER TABLE apps
    DROP COLUMN IF EXISTS backend_host;