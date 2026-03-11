CREATE TABLE IF NOT EXISTS tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    token_hash varchar(255) NOT NULL,
    expires_at timestamptz NOT NULL,
    is_revoked bool NOT NULL DEFAULT FALSE,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS tokens_user_id_idx ON tokens (user_id);

CREATE UNIQUE INDEX IF NOT EXISTS tokens_token_hash_user_id_idx ON tokens (user_id, token_hash);