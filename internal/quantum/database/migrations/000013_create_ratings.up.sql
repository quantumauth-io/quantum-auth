
-- ============================
-- App ratings (event table)
-- ============================

CREATE TABLE IF NOT EXISTS app_ratings (
                                           rating_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),

                                           app_id                UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
                                           rater_user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    -- Optional: link to a real purchase (strongly recommended)
                                           order_id              UUID NULL REFERENCES orders(order_id) ON DELETE SET NULL,

    -- 1..5 stars
                                           rating                SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),

    -- Optional review
                                           review                TEXT NULL,

    -- Optional structured signals (shipping speed, quality, etc.)
                                           tags                  JSONB NULL,

    -- Trust signals
                                           is_verified_purchase  BOOLEAN NOT NULL DEFAULT FALSE,

    -- Weight computed by your service (based on buyer reputation, verification, etc.)
                                           weight                NUMERIC(10,6) NOT NULL DEFAULT 1.0 CHECK (weight >= 0),

                                           created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
                                           updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- If marked verified, it must be tied to an order
                                           CONSTRAINT app_ratings_verified_requires_order CHECK (
                                               (NOT is_verified_purchase) OR (order_id IS NOT NULL)
                                               )
);

-- One rating per order (prevents spam on the same purchase)
CREATE UNIQUE INDEX IF NOT EXISTS ux_app_ratings_order
    ON app_ratings(order_id)
    WHERE order_id IS NOT NULL;

-- If no order (unverified rating), limit 1 per user per app
CREATE UNIQUE INDEX IF NOT EXISTS ux_app_ratings_unverified_once
    ON app_ratings(app_id, rater_user_id)
    WHERE order_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_app_ratings_app_created
    ON app_ratings(app_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_app_ratings_rater_created
    ON app_ratings(rater_user_id, created_at DESC);

-- Useful for “show reviews on product/app page”
CREATE INDEX IF NOT EXISTS ix_app_ratings_app_rating
    ON app_ratings(app_id, rating);

-- ============================
-- App reputation (rollup cache)
-- ============================

CREATE TABLE IF NOT EXISTS app_reputation (
                                              app_id                 UUID PRIMARY KEY REFERENCES apps(app_id) ON DELETE CASCADE,

    -- rating aggregates
                                              rating_count           BIGINT NOT NULL DEFAULT 0,
                                              rating_weight_sum      NUMERIC(20,6) NOT NULL DEFAULT 0,
                                              rating_weighted_sum    NUMERIC(20,6) NOT NULL DEFAULT 0, -- sum(rating * weight)
                                              rating_avg             NUMERIC(6,4) NOT NULL DEFAULT 0,   -- cached weighted avg

    -- operational trust signals
                                              orders_count           BIGINT NOT NULL DEFAULT 0,
                                              orders_volume          NUMERIC(38,0) NOT NULL DEFAULT 0,  -- base units
                                              disputes_count         BIGINT NOT NULL DEFAULT 0,
                                              disputes_won_count     BIGINT NOT NULL DEFAULT 0,
                                              disputes_lost_count    BIGINT NOT NULL DEFAULT 0,

                                              last_rating_at         TIMESTAMPTZ NULL,
                                              updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_app_reputation_updated
    ON app_reputation(updated_at DESC);

-- ============================
-- User reputation (buyer/rater rollup)
-- ============================

CREATE TABLE IF NOT EXISTS user_reputation (
                                               user_id                UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,

                                               purchases_count        BIGINT NOT NULL DEFAULT 0,
                                               purchases_volume       NUMERIC(38,0) NOT NULL DEFAULT 0,  -- base units

                                               disputes_filed_count   BIGINT NOT NULL DEFAULT 0,
                                               disputes_won_count     BIGINT NOT NULL DEFAULT 0,
                                               disputes_lost_count    BIGINT NOT NULL DEFAULT 0,

                                               ratings_left_count     BIGINT NOT NULL DEFAULT 0,

    -- baseline “trust weight” of this rater, computed by your service
                                               rater_weight           NUMERIC(10,6) NOT NULL DEFAULT 1.0 CHECK (rater_weight >= 0),

                                               updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_user_reputation_updated
    ON user_reputation(updated_at DESC);
