package postgres

import (
	"context"
	"go-auth-micro-service/internal/platform/db"
	"go-auth-micro-service/internal/users/domain"

	"github.com/jackc/pgx/v5"
)

type UserPostgres struct {
	db *db.Postgres
}

func NewUserRepository(db *db.Postgres) *UserPostgres {
	return &UserPostgres{db: db}
}

func (u *UserPostgres) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	query := `
		SELECT
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		FROM users
		WHERE id = $1
	`

	var user domain.User
	err := u.db.Pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)
	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}

func (u *UserPostgres) CreateUser(ctx context.Context, user *domain.User) (domain.User, error) {
	query := `
		INSERT INTO users (
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
	`

	err := u.db.Pool.QueryRow(ctx, query,
		user.ID,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Username,
		user.PasswordHash,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
		user.LastLoginAt,
	).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)
	if err != nil {
		return domain.User{}, err
	}

	return *user, nil
}

func (u *UserPostgres) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	query := `
		SELECT
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		FROM users
		WHERE email = $1
	`

	var user domain.User
	err := u.db.Pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)
	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}

func (u *UserPostgres) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	query := `
		SELECT
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		FROM users
		WHERE username = $1
	`

	var user domain.User
	err := u.db.Pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)
	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}

func (u *UserPostgres) EmailExists(ctx context.Context, email string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE email = $1
		)
	`

	var exists bool
	err := u.db.Pool.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, err
	}

	if exists {
		return true, nil
	}

	return false, nil
}

func (u *UserPostgres) UsernameExists(ctx context.Context, username string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE username = $1
		)
	`

	var exists bool
	err := u.db.Pool.QueryRow(ctx, query, username).Scan(&exists)
	if err != nil {
		return false, err
	}

	if exists {
		return true, nil
	}

	return false, nil
}

func (u *UserPostgres) UpdateUserPassword(ctx context.Context, userID string, newPasswordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $1
		WHERE id = $2
	`

	res, err := u.db.Pool.Exec(
		ctx,
		query,
		newPasswordHash,
		userID,
	)
	if err != nil {
		return err
	}

	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
