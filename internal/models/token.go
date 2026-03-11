package models

import (
	"database/sql"
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type Token struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	IsRevoked bool
	RevokedAt sql.NullTime
}