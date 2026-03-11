package models

import (
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type RolePermissions struct {
	ID           uuid.UUID
	RoleID       uuid.UUID
	PermissionID uuid.UUID
	CreatedAt    time.Time
}