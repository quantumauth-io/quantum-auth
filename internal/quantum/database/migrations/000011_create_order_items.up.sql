
CREATE TABLE IF NOT EXISTS order_items (
                                           order_item_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

                                           order_id               UUID NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
                                           product_id             UUID REFERENCES products(product_id) ON DELETE RESTRICT,

    -- Snapshot fields (immutable once created)
                                           product_type           product_type NOT NULL,
                                           product_name           VARCHAR(160) NOT NULL,
                                           product_slug           VARCHAR(200),

    -- Quantity (items/services). For subscriptions usually 1.
                                           quantity               BIGINT NOT NULL DEFAULT 1 CHECK (quantity > 0),

    -- Pricing snapshot (base units)
                                           unit_amount            NUMERIC(38,0) NOT NULL CHECK (unit_amount >= 0),
                                           line_total_amount      NUMERIC(38,0) NOT NULL CHECK (line_total_amount >= 0),

    -- Token snapshot (match order, but stored here to keep items self-describing)
                                           token_address          VARCHAR(66),
                                           token_decimals         SMALLINT NOT NULL DEFAULT 18 CHECK (token_decimals >= 0 AND token_decimals <= 36),

                                           created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
                                           updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Consistency: line_total_amount should equal unit_amount * quantity
                                           CONSTRAINT order_items_total_matches CHECK (
                                               line_total_amount = (unit_amount * quantity)
                                               )
);

-- Useful indexes
CREATE INDEX IF NOT EXISTS ix_order_items_order
    ON order_items(order_id);

CREATE INDEX IF NOT EXISTS ix_order_items_product
    ON order_items(product_id);
