package models

import (
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type Permission struct {
	ID          uuid.UUID
	Name        string
	Description string
	Resource    string
	Action      string
	IsActive    bool
	CreatedAt   time.Time
}
