package postgres

import (
	"context"
	"go-auth-micro-service/internal/db"
	"go-auth-micro-service/internal/models"
)

type UserPostgresRepository struct {
	db *db.Postgres
}

func NewUserRepository(db *db.Postgres) *UserPostgresRepository {
	return &UserPostgresRepository{db: db}
}

func (u *UserPostgresRepository) GetUserByID(ctx context.Context, id string) (models.User, error) {
	query := `
		SELECT
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		FROM users
		WHERE id = $1
	`

	var user models.User
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
		return models.User{}, err
	}

	return user, nil
}

func (u *UserPostgresRepository) CreateUser(ctx context.Context, user *models.User) (models.User, error) {
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
		return models.User{}, err
	}

	return *user, nil
}

func (u *UserPostgresRepository) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	query := `
		SELECT
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		FROM users
		WHERE email = $1
	`

	var user models.User
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
		return models.User{}, err
	}

	return user, nil
}

func (u *UserPostgresRepository) GetUserByUsername(ctx context.Context, username string) (models.User, error) {
	query := `
		SELECT
			id, first_name, last_name, email, username, password_hash,
			is_active, created_at, updated_at, last_login_at
		FROM users
		WHERE username = $1
	`

	var user models.User
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
		return models.User{}, err
	}

	return user, nil
}

func (u *UserPostgresRepository) EmailExists(ctx context.Context, email string) (bool, error) {
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

func (u *UserPostgresRepository) UsernameExists(ctx context.Context, username string) (bool, error) {
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
