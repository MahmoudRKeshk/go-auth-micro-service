CREATE TABLE IF NOT EXISTS tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    token_hash varchar(255) NOT NULL,
    expires_at timestamptz NOT NULL,
    is_revoked bool NOT NULL DEFAULT FALSE,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    refresh_token_id uuid NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (refresh_token_id) REFERENCES refresh_tokens(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS tokens_user_id_idx ON tokens (user_id);

CREATE INDEX IF NOT EXISTS token_refresh_token_id_idx ON tokens (refresh_token_id);

CREATE UNIQUE INDEX IF NOT EXISTS tokens_token_hash_user_id_idx ON tokens (user_id, token_hash);