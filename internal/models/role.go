package models

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type Role struct {
	ID          pgtype.UUID
	Name        string
	Description string
	IsActive    bool
	CreatedAt   time.Time
}