package models

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type Permission struct {
	ID          pgtype.UUID
	Name        string
	Description string
	Resource    string
	Action      string
	IsActive    bool
	CreatedAt   time.Time
}
