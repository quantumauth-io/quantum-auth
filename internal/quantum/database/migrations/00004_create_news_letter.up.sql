-- Create newsletter table
CREATE TABLE IF NOT EXISTS newsletter (
                                          newsletter_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

                                          email          VARCHAR(255) NOT NULL UNIQUE,
                                          subscribed     BOOLEAN      NOT NULL DEFAULT true,

                                          created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
                                          updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Create reusable updated_at trigger function (idempotent)
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger to newsletter table (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'newsletter_set_updated_at'
    ) THEN
        CREATE TRIGGER newsletter_set_updated_at
        BEFORE UPDATE ON newsletter
        FOR EACH ROW
        EXECUTE FUNCTION set_updated_at();
    END IF;
END;
$$;
