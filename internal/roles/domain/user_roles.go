package domain

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type UserRoles struct {
	ID         pgtype.UUID
	UserID     pgtype.UUID
	RoleID     pgtype.UUID
	AssignedAt time.Time
	AssignedBy pgtype.UUID
}