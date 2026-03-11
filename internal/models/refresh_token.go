package models

import (
	"database/sql"
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	IsRevoked  bool
	RevokedAt  sql.NullTime
	LastUsedAt sql.NullTime
	CreatedAt  time.Time
}