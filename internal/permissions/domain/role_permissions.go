package domain

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type RolePermissions struct {
	ID           pgtype.UUID
	RoleID       pgtype.UUID
	PermissionID pgtype.UUID
	CreatedAt    time.Time
}