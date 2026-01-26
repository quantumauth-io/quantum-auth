CREATE TABLE IF NOT EXISTS apps (
                                    app_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                    owner_user_id      UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

                                    name               VARCHAR(120) NOT NULL,
                                    description        TEXT,
                                    domain             VARCHAR(253) NOT NULL,

                                    tier               VARCHAR(16) NOT NULL DEFAULT 'free'
                                        CHECK (tier IN ('free', 'premium')),

                                    verification_token VARCHAR(64) NOT NULL,
                                    verified           BOOLEAN NOT NULL DEFAULT FALSE,
                                    last_verified_at   TIMESTAMPTZ,
                                    last_checked_at    TIMESTAMPTZ,

                                    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
                                    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS apps_domain_unique_ci ON apps (lower(domain));
CREATE INDEX IF NOT EXISTS apps_owner_user_id_idx ON apps (owner_user_id);