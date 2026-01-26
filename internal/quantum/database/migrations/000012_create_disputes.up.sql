-- 00005_create_disputes.up.sql

-- ============================
-- Enums
-- ============================

DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dispute_status') THEN
            CREATE TYPE dispute_status AS ENUM (
                'opened',        -- buyer opened dispute
                'under_review',  -- your system / arbitrators reviewing
                'merchant_responded',
                'resolved',      -- final decision made
                'cancelled'      -- withdrawn/invalidated
                );
        END IF;
    END
$$;

DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dispute_outcome') THEN
            CREATE TYPE dispute_outcome AS ENUM (
                'buyer_wins',
                'merchant_wins',
                'split',
                'unknown'
                );
        END IF;
    END
$$;

-- ============================
-- Disputes table
-- ============================

CREATE TABLE IF NOT EXISTS disputes (
                                        dispute_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),

                                        order_id              UUID NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,

    -- who opened it (start with buyer, but keep generic)
                                        opened_by_user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,

                                        status                dispute_status NOT NULL DEFAULT 'opened',
                                        outcome               dispute_outcome NOT NULL DEFAULT 'unknown',

                                        reason_code           VARCHAR(64),   -- e.g. "not_received", "not_as_described"
                                        reason_text           TEXT,

    -- Evidence can be links/hashes; keep flexible
                                        evidence              JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Workflow timestamps
                                        opened_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
                                        merchant_responded_at TIMESTAMPTZ,
                                        resolved_at           TIMESTAMPTZ,
                                        cancelled_at          TIMESTAMPTZ,

    -- Optional: resolution details
                                        resolution_note       TEXT,

    -- Optional: on-chain actions
                                        refund_tx_hash        VARCHAR(80),
                                        release_tx_hash       VARCHAR(80),

                                        created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
                                        updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Sanity
                                        CONSTRAINT disputes_hash_format_refund CHECK (
                                            refund_tx_hash IS NULL OR length(refund_tx_hash) >= 8
                                            ),
                                        CONSTRAINT disputes_hash_format_release CHECK (
                                            release_tx_hash IS NULL OR length(release_tx_hash) >= 8
                                            )
);

-- ============================
-- Constraints / Indexes
-- ============================

-- Only one "active" dispute per order.
-- (Resolved/cancelled disputes can exist historically.)
CREATE UNIQUE INDEX IF NOT EXISTS ux_disputes_one_active_per_order
    ON disputes(order_id)
    WHERE status IN ('opened', 'under_review', 'merchant_responded');

CREATE INDEX IF NOT EXISTS ix_disputes_order
    ON disputes(order_id);

CREATE INDEX IF NOT EXISTS ix_disputes_status
    ON disputes(status);

CREATE INDEX IF NOT EXISTS ix_disputes_opened_by
    ON disputes(opened_by_user_id, opened_at DESC);
