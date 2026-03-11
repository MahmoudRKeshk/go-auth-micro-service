CREATE TABLE IF NOT EXISTS permissions (
    id uuid PRIMARY KEY,
    name varchar(255) UNIQUE NOT NULL,
    description varchar(255) NOT NULL,
    resource varchar(255) NOT NULL,
    action varchar(255) NOT NULL,
    is_active bool NOT NULL DEFAULT TRUE,
    created_at timestamptz NOT NULL DEFAULT now()
);