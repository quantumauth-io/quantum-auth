
-- ============================
-- Enums
-- ============================

DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'order_status') THEN
            CREATE TYPE order_status AS ENUM (
                'created',          -- order created, awaiting payment
                'paid',             -- payment seen/confirmed
                'in_escrow',        -- escrow active (usually immediately after paid)
                'disputed',         -- dispute filed, funds frozen
                'released',         -- merchant claimed funds / escrow released
                'cancelled',        -- cancelled before payment
                'refunded'          -- refunded (partial/full; details stored elsewhere)
                );
        END IF;
    END
$$;

-- ============================
-- Orders table
-- ============================

CREATE TABLE IF NOT EXISTS orders (
                                      order_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ownership / parties
                                      app_id                UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
                                      buyer_user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,

    -- order state
                                      status                order_status NOT NULL DEFAULT 'created',

    -- Amounts (token-based)
    -- total_amount is in "token base units" (or decimal units) depending on your convention.
    -- Pick ONE convention and stick to it. Most teams store decimal human units + decimals.
                                      total_amount          NUMERIC(38, 0) NOT NULL CHECK (total_amount >= 0),

    -- Token used for payment (native token => NULL address, or use a sentinel like '0x0')
                                      token_address         VARCHAR(66), -- 0x... (up to 42), but allow longer for future formats
                                      token_decimals        SMALLINT NOT NULL DEFAULT 18 CHECK (token_decimals >= 0 AND token_decimals <= 36),

    -- Chain/payment tracking
                                      chain_id              BIGINT NOT NULL CHECK (chain_id > 0),

                                      payment_tx_hash       VARCHAR(80),  -- e.g. 0x... 66 chars, but keep headroom
                                      payment_confirmed_at  TIMESTAMPTZ,  -- when you consider it final enough
                                      paid_at               TIMESTAMPTZ,  -- set when order transitions to paid/in_escrow

    -- Escrow window (7 days default; rating may shorten later)
                                      escrow_release_at     TIMESTAMPTZ,

    -- Claim/release on chain (optional; depends if escrow is on-chain)
                                      release_tx_hash       VARCHAR(80),
                                      released_at           TIMESTAMPTZ,

    -- Dispute window tracking (optional but useful)
                                      dispute_filed_at      TIMESTAMPTZ,
                                      dispute_reason        TEXT,

    -- Extensibility
                                      metadata              JSONB NOT NULL DEFAULT '{}'::jsonb,

                                      created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
                                      updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Basic sanity constraints
                                      CONSTRAINT orders_payment_tx_hash_format CHECK (
                                          payment_tx_hash IS NULL OR length(payment_tx_hash) >= 8
                                          ),

                                      CONSTRAINT orders_release_tx_hash_format CHECK (
                                          release_tx_hash IS NULL OR length(release_tx_hash) >= 8
                                          ),

    -- If paid, we expect paid_at and escrow_release_at
                                      CONSTRAINT orders_paid_requires_timestamps CHECK (
                                          status NOT IN ('paid', 'in_escrow', 'disputed', 'released', 'refunded')
                                              OR (paid_at IS NOT NULL AND escrow_release_at IS NOT NULL)
                                          )
);

-- ============================
-- Uniqueness / indexes
-- ============================

-- Prevent the same on-chain payment tx being attached twice
CREATE UNIQUE INDEX IF NOT EXISTS ux_orders_chain_payment_tx
    ON orders(chain_id, payment_tx_hash)
    WHERE payment_tx_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_orders_app_created
    ON orders(app_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_orders_buyer_created
    ON orders(buyer_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_orders_status
    ON orders(status);

CREATE INDEX IF NOT EXISTS ix_orders_escrow_release_at
    ON orders(escrow_release_at)
    WHERE status IN ('paid', 'in_escrow');
