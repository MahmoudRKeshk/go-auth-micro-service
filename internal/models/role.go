package models

import (
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	IsActive    bool
	CreatedAt   time.Time
}