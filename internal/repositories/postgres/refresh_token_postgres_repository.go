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

func (r *RefreshTokenPostgresRepository) InsertRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (
			id, user_id, token_hash, expires_at, is_revoked, revoked_at, last_used_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	res, err := r.db.Pool.Exec(ctx, query,
		refreshToken.ID,
		refreshToken.UserID,
		refreshToken.TokenHash,
		refreshToken.ExpiresAt,
		refreshToken.IsRevoked,
		refreshToken.RevokedAt,
		refreshToken.LastUsedAt,
		refreshToken.CreatedAt,
	)

	if err != nil || res.RowsAffected() == 0 {
		return err
	}

	return nil
}

func (r *RefreshTokenPostgresRepository) IsRefreshTokenRevoked(ctx context.Context, refreshTokenHash string) (bool, error) {
	query := `
		SELECT is_revoked
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	var isRevoked bool

	err := r.db.Pool.QueryRow(ctx, query, refreshTokenHash).Scan(&isRevoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// TODO: later handle missing refresh token
			return true, nil
		}
		return false, err
	}

	return isRevoked, nil
}
