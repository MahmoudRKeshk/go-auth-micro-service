CREATE TABLE IF NOT EXISTS role_permissions (
    id uuid PRIMARY KEY,
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE INDEX IF NOT EXISTS role_permissions_role_id_idx ON role_permissions (role_id);

CREATE INDEX IF NOT EXISTS role_permissions_permission_id_idx ON role_permissions (permission_id);

CREATE UNIQUE INDEX IF NOT EXISTS role_permissions_role_id_permission_id_idx ON role_permissions (role_id, permission_id);