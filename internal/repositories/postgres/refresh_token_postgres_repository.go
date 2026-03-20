package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"go-auth-micro-service/internal/db"
	"go-auth-micro-service/internal/models"
)

type RefreshTokenPostgresRepository struct {
	db *db.Postgres
}

func NewRefreshTokenRepository(db *db.Postgres) *RefreshTokenPostgresRepository {
	return &RefreshTokenPostgresRepository{db: db}
}

func (r *RefreshTokenPostgresRepository) GetRefreshTokenByTokenHashAndUserID(ctx context.Context, refreshTokenHash string, userID string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, is_revoked, revoked_at, last_used_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`

	var refreshToken models.RefreshToken

	err := r.db.Pool.QueryRow(ctx, query, refreshTokenHash, userID).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.TokenHash,
		&refreshToken.ExpiresAt,
		&refreshToken.IsRevoked,
		&refreshToken.RevokedAt,
		&refreshToken.LastUsedAt,
		&refreshToken.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

func (r *RefreshTokenPostgresRepository) InsertRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) (*models.RefreshToken, error) {
	query := `
		INSERT INTO refresh_tokens (
			id, user_id, token_hash, expires_at, is_revoked, revoked_at, last_used_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`
	err := r.db.Pool.QueryRow(ctx, query,
		refreshToken.ID,
		refreshToken.UserID,
		refreshToken.TokenHash,
		refreshToken.ExpiresAt,
		refreshToken.IsRevoked,
		refreshToken.RevokedAt,
		refreshToken.LastUsedAt,
		refreshToken.CreatedAt,
	).Scan(
		&refreshToken.ID,
	)

	if err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (r *RefreshTokenPostgresRepository) IsRefreshTokenRevoked(ctx context.Context, refreshTokenHash string, userID string) (bool, error) {
	query := `
		SELECT is_revoked
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`

	var isRevoked bool

	err := r.db.Pool.QueryRow(ctx, query, refreshTokenHash, userID).Scan(&isRevoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// TODO: later handle missing refresh token
			return true, nil
		}
		return false, err
	}

	return isRevoked, nil
}

func (r *RefreshTokenPostgresRepository) RevokeNonExpiredRefreshTokens(ctx context.Context, userId string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = now()
		WHERE user_id = $1 AND expires_at > now() AND is_revoked = false
	`
	_, err := r.db.Pool.Exec(
		ctx,
		query,
		userId,
	)

	return err
}

func (r *RefreshTokenPostgresRepository) RevokeRefreshToken(ctx context.Context, refreshTokenHash string, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = now()
		WHERE token_hash = $1 AND user_id = $2
	`
	_, err := r.db.Pool.Exec(
		ctx,
		query,
		refreshTokenHash,
		userID,
	)

	return err
}
