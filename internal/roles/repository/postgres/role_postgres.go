package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"go-auth-micro-service/internal/platform/db"
	"go-auth-micro-service/internal/roles/domain"
)

type RolePostgres struct {
	db *db.Postgres
}

func NewRoleRepository(db *db.Postgres) *RolePostgres {
	return &RolePostgres{db: db}
}

func (r *RolePostgres) GetActiveRoleByID(ctx context.Context, id string) (*domain.Role, error) {
	query := `
		SELECT
			id, name, description, is_active, created_at
		FROM roles
		WHERE id = $1 AND is_active = true
	`

	var role domain.Role

	err := r.db.Pool.QueryRow(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.IsActive,
		&role.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

func (r *RolePostgres) GetRoleByID(ctx context.Context, id string) (*domain.Role, error) {
	query := `
		SELECT
			id, name, description, is_active, created_at
		FROM roles
		WHERE id = $1
	`

	var role domain.Role

	err := r.db.Pool.QueryRow(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.IsActive,
		&role.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

func (r *RolePostgres) CreateRole(ctx context.Context, role *domain.Role) (*domain.Role, error) {
	query := `
		INSERT INTO roles (
			id, name, description, is_active, created_at
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING
			id, name, description, is_active, created_at
	`

	err := r.db.Pool.QueryRow(ctx, query,
		role.ID,
		role.Name,
		role.Description,
		role.IsActive,
		role.CreatedAt,
	).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.IsActive,
		&role.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return role, nil
}

func (r *RolePostgres) DeactivateRole(ctx context.Context, id string) error {
	query := `
		UPDATE roles
		SET is_active = false
		WHERE id = $1
	`
	res, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *RolePostgres) ActivateRole(ctx context.Context, id string) error {
	query := `
		UPDATE roles
		SET is_active = true
		WHERE id = $1
	`
	res, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *RolePostgres) GetActiveRoles(ctx context.Context) ([]*domain.Role, error) {
	query := `
		SELECT id, name, description, is_active, created_at
		FROM roles
		WHERE is_active = true
	`
	rows, err := r.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*domain.Role
	for rows.Next() {
		var role domain.Role
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.IsActive,
			&role.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *RolePostgres) GetRolesByUserID(ctx context.Context, userID string) ([]*domain.Role, error) {
	query := `
		SELECT roles.id, roles.name, roles.description, roles.is_active, roles.created_at
		FROM roles
		INNER JOIN user_roles ON roles.id = user_roles.role_id
		WHERE user_roles.user_id = $1
	`
	rows, err := r.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*domain.Role
	for rows.Next() {
		var role domain.Role
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.IsActive,
			&role.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *RolePostgres) DeleteRolesFromUser(ctx context.Context, userID string) error {
	query := `
		DELETE FROM user_roles
		WHERE user_id = $1
	`
	_, err := r.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return err
	}
	return nil
}

func (r *RolePostgres) AddRoleToUser(ctx context.Context, userRole domain.UserRoles) error {
	query := `
		INSERT INTO user_roles (id,user_id, role_id, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.db.Pool.Exec(ctx, query, userRole.ID, userRole.UserID, userRole.RoleID, userRole.AssignedAt, userRole.AssignedBy)
	if err != nil {
		return err
	}
	return nil
}
