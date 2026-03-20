package models

import (
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type Token struct {
	ID        pgtype.UUID
	UserID    pgtype.UUID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	IsRevoked bool
	RevokedAt sql.NullTime
	RefreshTokenID pgtype.UUID
}