package postgres

import (
	"context"
	"go-auth-micro-service/internal/db"
	"go-auth-micro-service/internal/models"
)

type TokenPostgresRepository struct {
	db *db.Postgres
}

func NewTokenRepository(db *db.Postgres) *TokenPostgresRepository {
	return &TokenPostgresRepository{db: db}
}

func (t *TokenPostgresRepository) InsertToken(ctx context.Context, token *models.Token) error {
	query := `
		INSERT INTO tokens (
			id, user_id, token_hash, expires_at, is_revoked, revoked_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	res, err := t.db.Pool.Exec(
		ctx,
		query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
		token.IsRevoked,
		token.RevokedAt,
		token.CreatedAt,
	)

	if err != nil || res.RowsAffected() == 0 {
		return err
	}

	return nil
}

func (t *TokenPostgresRepository) RevokeNonExpiredTokens(ctx context.Context, userId string) error {
	query := `
		UPDATE tokens
		SET is_revoked = true, revoked_at = now()
		WHERE user_id = $1 AND expires_at > now() AND is_revoked = false
	`
	_, err := t.db.Pool.Exec(
		ctx,
		query,
		userId,
	)

	return err
}

func (t *TokenPostgresRepository) RevokeToken(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE tokens
		SET is_revoked = true, revoked_at = now()
		WHERE token_hash = $1 AND is_revoked = false
	`
	_, err := t.db.Pool.Exec(
		ctx,
		query,
		tokenHash,
	)

	return err
}
