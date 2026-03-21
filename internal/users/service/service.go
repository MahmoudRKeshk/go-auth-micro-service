package service

import (
	"context"
	"github.com/jackc/pgx/v5"
	authrepo "go-auth-micro-service/internal/auth/repository"
	"go-auth-micro-service/internal/shared/errs"
	"go-auth-micro-service/internal/users/repository"
	"sync"
)

type UserService struct {
	userRepo         repository.UserRepository
	tokenRepo        authrepo.TokenRepository
	refreshTokenRepo authrepo.RefreshTokenRepository
}

func NewUserService(userRepo repository.UserRepository, tokenRepo authrepo.TokenRepository, refreshTokenRepo authrepo.RefreshTokenRepository) *UserService {
	return &UserService{userRepo: userRepo, tokenRepo: tokenRepo, refreshTokenRepo: refreshTokenRepo}
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

	wg := sync.WaitGroup{}
	var delUsrErr error
	var delRefreshTokenErr error
	var delTokenErr error

	wg.Go(func() {
		delUsrErr = u.userRepo.DeleteUser(ctx, userID)
	})
	wg.Go(func() {
		delRefreshTokenErr = u.refreshTokenRepo.RevokeNonExpiredRefreshTokens(ctx, userID)
	})
	wg.Go(func() {
		delTokenErr = u.tokenRepo.RevokeNonExpiredTokens(ctx, userID)
	})

	wg.Wait()
	if delUsrErr != nil {
		if delUsrErr == pgx.ErrNoRows {
			return &errs.AppError{
				Code:    errs.CodeNotFound,
				Message: "user not found",
				Err:     delUsrErr,
				Details: nil,
			}
		}
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to delete user",
			Err:     delUsrErr,
			Details: nil,
		}
	}
	if delRefreshTokenErr != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to revoke refresh tokens",
			Err:     delRefreshTokenErr,
			Details: nil,
		}
	}
	if delTokenErr != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to revoke tokens",
			Err:     delTokenErr,
			Details: nil,
		}
	}
	return nil
}
