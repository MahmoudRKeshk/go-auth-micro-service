package repository

import (
	"context"
	"go-auth-micro-service/internal/users/domain"
)

type UserRepository interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	CreateUser(ctx context.Context, user *domain.User) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	EmailExists(ctx context.Context, email string) (bool, error)
	UsernameExists(ctx context.Context, username string) (bool, error)
	UpdateUserPassword(ctx context.Context, userID string, newPasswordHash string) error
}
