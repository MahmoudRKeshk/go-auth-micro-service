package domain

import (
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type RefreshToken struct {
	ID         pgtype.UUID
	UserID     pgtype.UUID
	TokenHash  string
	ExpiresAt  time.Time
	IsRevoked  bool
	RevokedAt  sql.NullTime
	LastUsedAt sql.NullTime
	CreatedAt  time.Time
}