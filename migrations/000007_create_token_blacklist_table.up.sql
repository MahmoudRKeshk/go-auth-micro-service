CREATE TABLE IF NOT EXISTS token_blacklist (
    id uuid PRIMARY KEY,
    token_hash varchar(255) NOT NULL,
    user_id uuid NOT NULL,
    reason varchar(255) NOT NULL,
    blocked_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS token_blacklist_user_id_idx ON token_blacklist (user_id);

CREATE UNIQUE INDEX IF NOT EXISTS token_blacklist_token_hash_user_id_idx ON token_blacklist (user_id, token_hash);