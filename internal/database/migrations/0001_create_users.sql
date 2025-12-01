-- 0001_create_users.sql

CREATE TABLE IF NOT EXISTS users (
                                     user_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                     username      VARCHAR(255) NOT NULL UNIQUE,
                                     email         VARCHAR(255) NOT NULL UNIQUE,
                                     password_hash CHAR(64)     NOT NULL,
                                     first_name    VARCHAR(255),
                                     last_name     VARCHAR(255),
                                     created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
