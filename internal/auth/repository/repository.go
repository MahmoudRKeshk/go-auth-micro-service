package repository

import (
	"context"
	"go-auth-micro-service/internal/auth/domain"
)

type RefreshTokenRepository interface {
	GetRefreshTokenByTokenHashAndUserID(ctx context.Context, refreshTokenHash string, userID string) (*domain.RefreshToken, error)
	InsertRefreshToken(ctx context.Context, refreshToken *domain.RefreshToken) (*domain.RefreshToken, error)
	IsRefreshTokenRevoked(ctx context.Context, refreshTokenHash string, userID string) (bool, error)
	RevokeNonExpiredRefreshTokens(ctx context.Context, userId string) error
	RevokeRefreshToken(ctx context.Context, refreshTokenHash string, userID string) error
}

type TokenRepository interface {
	InsertToken(ctx context.Context, token *domain.Token) error
	RevokeNonExpiredTokens(ctx context.Context, userId string) error
	RevokeToken(ctx context.Context, tokenHash string) error
	IsTokenRevoked(ctx context.Context, tokenHash string) (bool, error)
}
