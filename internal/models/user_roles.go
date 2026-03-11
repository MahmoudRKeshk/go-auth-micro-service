package models

import (
	"time"

	uuid "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type UserRoles struct {
	ID         uuid.UUID 
	UserID     uuid.UUID 
	RoleID     uuid.UUID 
	AssignedAt time.Time 
	AssignedBy uuid.UUID     
}