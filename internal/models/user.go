package models

import (
	"database/sql"
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type User struct {
	ID           uuid.UUID
	FirstName    string
	LastName     string
	Email        string
	Username     string
	PasswordHash string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  sql.NullTime
}