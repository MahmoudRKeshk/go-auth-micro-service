CREATE TABLE IF NOT EXISTS user_roles(
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    assigned_by uuid NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (assigned_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS user_roles_user_id_idx ON user_roles (user_id);

CREATE INDEX IF NOT EXISTS user_roles_role_id_idx ON user_roles (role_id);

CREATE UNIQUE INDEX IF NOT EXISTS user_roles_user_id_role_id_idx ON user_roles (user_id, role_id);