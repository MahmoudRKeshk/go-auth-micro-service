package models

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type TokenBlacklist struct {
	ID        pgtype.UUID
	TokenHash string
	UserID    pgtype.UUID
	Reason    string
	BlockedAt time.Time
	ExpiresAt time.Time
	CreatedAt time.Time
}