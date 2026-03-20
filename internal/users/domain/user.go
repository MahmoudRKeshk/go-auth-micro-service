package domain

import (
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type User struct {
	ID           pgtype.UUID
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