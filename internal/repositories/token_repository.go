package repositories

import (
	"context"
	"go-auth-micro-service/internal/models"
)

type TokenRepository interface {
	InsertToken(ctx context.Context, token *models.Token) error
}
