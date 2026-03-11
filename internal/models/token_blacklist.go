package models

import (
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type TokenBlacklist struct {
	ID        uuid.UUID    
	TokenHash string       
	UserID    uuid.UUID    
	Reason    string       
	BlockedAt time.Time
	ExpiresAt time.Time
	CreatedAt time.Time 
}