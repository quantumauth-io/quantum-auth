
-- ============================
-- Enums
-- ============================

DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'product_type') THEN
            CREATE TYPE product_type AS ENUM (
                'item',
                'service',
                'subscription'
                );
        END IF;
    END
$$;

DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'billing_interval_unit') THEN
            CREATE TYPE billing_interval_unit AS ENUM (
                'day',
                'week',
                'month',
                'year'
                );
        END IF;
    END
$$;

-- ============================
-- Products table
-- ============================

CREATE TABLE IF NOT EXISTS products (
                                        product_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Ownership
                                        app_id                 UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,

    -- Core info
                                        type                   product_type NOT NULL,
                                        name                   VARCHAR(160) NOT NULL,
                                        description            TEXT,

    -- URL-friendly identifier (unique per app)
                                        slug                   VARCHAR(200) NOT NULL,

    -- Pricing
                                        price_amount           NUMERIC(20,6) NOT NULL CHECK (price_amount >= 0),
                                        price_currency         VARCHAR(10) NOT NULL DEFAULT 'USD',

    -- Subscription configuration (only for type = 'subscription')
                                        billing_interval_count INTEGER CHECK (billing_interval_count IS NULL OR billing_interval_count >= 1),
                                        billing_interval_unit  billing_interval_unit,
                                        billing_anchor         VARCHAR(16)
                                            CHECK (billing_anchor IS NULL OR billing_anchor IN ('purchase_date')),

    -- Inventory (mainly for items)
                                        stock_quantity         BIGINT CHECK (stock_quantity IS NULL OR stock_quantity >= 0),

    -- Cached counters (UI / analytics)
                                        sold_count             BIGINT NOT NULL DEFAULT 0 CHECK (sold_count >= 0),

    -- Status
                                        is_active              BOOLEAN NOT NULL DEFAULT TRUE,

    -- Extensibility
                                        metadata               JSONB NOT NULL DEFAULT '{}'::jsonb,

                                        created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
                                        updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Constraints
                                        CONSTRAINT products_slug_unique_per_app UNIQUE (app_id, slug),

                                        CONSTRAINT products_subscription_fields_required CHECK (
                                            type <> 'subscription'
                                                OR (
                                                billing_interval_count IS NOT NULL
                                                    AND billing_interval_unit IS NOT NULL
                                                    AND billing_anchor IS NOT NULL
                                                )
                                            ),

                                        CONSTRAINT products_non_subscription_fields_empty CHECK (
                                            type = 'subscription'
                                                OR (
                                                billing_interval_count IS NULL
                                                    AND billing_interval_unit IS NULL
                                                    AND billing_anchor IS NULL
                                                )
                                            )
);

-- ============================
-- Indexes
-- ============================

CREATE INDEX IF NOT EXISTS ix_products_app
    ON products(app_id);

CREATE INDEX IF NOT EXISTS ix_products_app_active
    ON products(app_id, is_active);

CREATE INDEX IF NOT EXISTS ix_products_app_type
    ON products(app_id, type);
