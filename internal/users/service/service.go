package service

import (
	"context"
	authrepo "go-auth-micro-service/internal/auth/repository"
	"go-auth-micro-service/internal/platform/db"
	"go-auth-micro-service/internal/shared/errs"
	"go-auth-micro-service/internal/users/repository"

	"github.com/jackc/pgx/v5"
)

type UserService struct {
	userRepo         repository.UserRepository
	tokenRepo        authrepo.TokenRepository
	refreshTokenRepo authrepo.RefreshTokenRepository
	db               *db.Postgres
}

func NewUserService(userRepo repository.UserRepository, tokenRepo authrepo.TokenRepository, refreshTokenRepo authrepo.RefreshTokenRepository, db *db.Postgres) *UserService {
	return &UserService{userRepo: userRepo, tokenRepo: tokenRepo, refreshTokenRepo: refreshTokenRepo, db: db}
}

func (u *UserService) GetUserByID(ctx context.Context, id string) (*UserResult, *errs.AppError) {
	user, err := u.userRepo.GetUserByID(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, &errs.AppError{
				Code:    errs.CodeNotFound,
				Message: "user not found",
				Err:     err,
				Details: nil,
			}
		}
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to get user",
			Err:     err,
			Details: nil,
		}
	}
	if user.IsActive == false {
		return nil, &errs.AppError{
			Code:    errs.CodeNotFound,
			Message: "user not found",
			Err:     err,
			Details: nil,
		}
	}

	res := &UserResult{
		ID:        user.ID.String(),
		Username:  user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
	}

	return res, nil
}

func (u *UserService) DeleteUser(ctx context.Context, userID string) *errs.AppError {
	// TODO: introduce transaction here between refresh token and token
	tx, err := u.db.Pool.Begin(ctx)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to begin transaction",
			Err:     err,
			Details: nil,
		}
	}
	var txErr error
	defer func() {
		if txErr != nil {
			tx.Rollback(ctx)
		} else {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				// TODO: handle commit errors and log them properly
			}
		}
	}()

	txErr = u.refreshTokenRepo.RevokeNonExpiredRefreshTokens(ctx, userID)
	if txErr != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to revoke refresh tokens",
			Err:     txErr,
			Details: nil,
		}
	}

	txErr = u.tokenRepo.RevokeNonExpiredTokens(ctx, userID)
	if txErr != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to revoke tokens",
			Err:     txErr,
			Details: nil,
		}
	}

	txErr = u.userRepo.DeleteUser(ctx, userID)
	if txErr != nil {
		if txErr == pgx.ErrNoRows {
			return &errs.AppError{
				Code:    errs.CodeNotFound,
				Message: "user not found",
				Err:     txErr,
				Details: nil,
			}
		}
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to delete user",
			Err:     txErr,
			Details: nil,
		}
	}

	return nil
}
