package repository

import (
	"context"
	"go-auth-micro-service/internal/roles/domain"
)

type RoleRepository interface {
	GetActiveRoleByID(ctx context.Context, id string) (*domain.Role, error)
	GetRoleByID(ctx context.Context, id string) (*domain.Role, error)
	CreateRole(ctx context.Context, role *domain.Role) (*domain.Role, error)
	DeactivateRole(ctx context.Context, id string) error
	ActivateRole(ctx context.Context, id string) error // Idempotent
	GetActiveRoles(ctx context.Context) ([]*domain.Role, error)
	GetRolesByUserID(ctx context.Context, userID string) ([]*domain.Role, error)
	DeleteRolesFromUser(ctx context.Context, userID string) error // Idempotent
	AddRoleToUser(ctx context.Context, userRole domain.UserRoles) error
}
