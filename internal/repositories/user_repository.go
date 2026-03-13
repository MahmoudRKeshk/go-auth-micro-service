package repositories

import (
	"context"
	"go-auth-micro-service/internal/models"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) (models.User, error)
	GetUserByEmail(ctx context.Context, email string) (models.User, error)
	GetUserByUsername(ctx context.Context, username string) (models.User, error)
	EmailExists(ctx context.Context, email string) (bool, error)
	UsernameExists(ctx context.Context, username string) (bool, error)
}
