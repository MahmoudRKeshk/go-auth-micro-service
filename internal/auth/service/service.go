package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	authdomain "go-auth-micro-service/internal/auth/domain"
	authrepo "go-auth-micro-service/internal/auth/repository"
	"go-auth-micro-service/internal/platform/security"
	"go-auth-micro-service/internal/shared/errs"
	"go-auth-micro-service/internal/shared/utils"
	usersdomain "go-auth-micro-service/internal/users/domain"
	userrepo "go-auth-micro-service/internal/users/repository"
	"golang.org/x/crypto/bcrypt"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"
)

type AuthService struct {
	userRepo         userrepo.UserRepository
	refreshTokenRepo authrepo.RefreshTokenRepository
	tokenRepo        authrepo.TokenRepository
	jwt              security.JwtService
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func NewUserService(ur userrepo.UserRepository, refreshTokenRepo authrepo.RefreshTokenRepository, tokenRepo authrepo.TokenRepository, jwt security.JwtService) *AuthService {
	return &AuthService{userRepo: ur, refreshTokenRepo: refreshTokenRepo, tokenRepo: tokenRepo, jwt: jwt}
}

func (authSrv *AuthService) CreateUser(ctx context.Context, input RegisterInput) *errs.AppError {
	if err := authSrv.validateRegisterRequest(input); err != nil {
		return err
	}

	email := strings.TrimSpace(input.Email)
	username := strings.TrimSpace(input.Username)
	firstName := strings.TrimSpace(input.FirstName)
	lastName := strings.TrimSpace(input.LastName)

	// Check if email already exists
	emailExists, err := authSrv.userRepo.EmailExists(ctx, email)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to create user: failed to check if email exists",
			Err:     err,
			Details: nil,
		}
	}
	if emailExists {
		return &errs.AppError{
			Code:    errs.CodeConflict,
			Message: "email already exists: email is already registered",
			Err:     nil,
			Details: map[string]string{"email": "email is already registered"},
		}
	}

	// Check if username already exists
	usernameExists, err := authSrv.userRepo.UsernameExists(ctx, username)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to create user",
			Err:     err,
			Details: nil,
		}
	}
	if usernameExists {
		return &errs.AppError{
			Code:    errs.CodeConflict,
			Message: "username already exists: username is already taken",
			Err:     nil,
			Details: map[string]string{"username": "username is already taken"},
		}
	}

	passwordHash, err := utils.HashPassword(input.Password)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to create user: failed to hash password",
			Err:     err,
			Details: nil,
		}
	}

	rawID, err := uuid.NewV4()
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to create user: failed to generate user id",
			Err:     err,
			Details: nil,
		}
	}

	user := &usersdomain.User{
		ID:           pgtype.UUID{Bytes: rawID, Valid: true},
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		Username:     username,
		PasswordHash: passwordHash,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastLoginAt:  sql.NullTime{},
	}

	createdUser, err := authSrv.userRepo.CreateUser(ctx, user)
	if err != nil {
		fmt.Printf("failed to create user: %v\n", err)
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to create user: failed to create user",
			Err:     err,
			Details: nil,
		}
	}

	_ = createdUser

	return nil
}

func (authSrv *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, *errs.AppError) {
	if err := authSrv.validateLoginRequest(input); err != nil {
		return nil, err
	}

	email := strings.TrimSpace(input.Email)
	password := strings.TrimSpace(input.Password)

	user, err := authSrv.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeNotFound,
			Message: "user not found: email not found",
			Err:     err,
			Details: map[string]string{
				"email": "email not found",
			},
		}
	}

	isPasswordValid := utils.CheckPasswordHash(password, user.PasswordHash)
	if !isPasswordValid {
		return nil, &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "invalid credentials: invalid password",
			Err:     nil,
			Details: nil,
		}
	}

	refreshToken, err := authSrv.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Hour*24*7))
	accessToken, err := authSrv.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Minute*15))
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}

	rawID, err := uuid.NewV4()
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}

	refreshTokenHash := utils.HashToken(refreshToken)
	accessTokenHash := utils.HashToken(accessToken)

	refreshTokenEntity := &authdomain.RefreshToken{
		ID:         pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:     user.ID,
		TokenHash:  refreshTokenHash,
		ExpiresAt:  time.Now().Add(time.Hour * 24 * 7),
		IsRevoked:  false,
		RevokedAt:  sql.NullTime{},
		LastUsedAt: sql.NullTime{},
		CreatedAt:  time.Now(),
	}

	// TODO: introduce transaction here between refresh token and token
	refreshTokenEntity, err = authSrv.refreshTokenRepo.InsertRefreshToken(ctx, refreshTokenEntity)
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to insert refresh token",
			Err:     err,
			Details: nil,
		}
	}

	tokenEntity := authdomain.Token{
		ID:             pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:         user.ID,
		TokenHash:      accessTokenHash,
		ExpiresAt:      time.Now().Add(time.Minute * 15),
		CreatedAt:      time.Now(),
		IsRevoked:      false,
		RevokedAt:      sql.NullTime{},
		RefreshTokenID: refreshTokenEntity.ID,
	}

	err = authSrv.tokenRepo.InsertToken(ctx, &tokenEntity)
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to insert access token",
			Err:     err,
			Details: nil,
		}
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (authSrv *AuthService) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, *errs.AppError) {
	if err := authSrv.validateRefreshRequest(input); err != nil {
		return nil, err
	}

	oldToken := strings.TrimSpace(input.RefreshToken)

	parsedRefreshToken, err := authSrv.jwt.ParseToken(oldToken)
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to parse refresh token",
			Err:     err,
			Details: nil,
		}
	}
	userID, ok := parsedRefreshToken["userId"].(string)
	if !ok || userID == "" {
		return nil, &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to fetch user id from the context",
			Err:     err,
			Details: nil,
		}
	}

	expTime, err := parsedRefreshToken.GetExpirationTime()
	if err != nil || expTime == nil {
		return nil, &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to fetch expiration time from the refresh token",
			Err:     err,
			Details: nil,
		}
	}

	if time.Now().After(expTime.Time) {
		return nil, &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "refresh token expired",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has expired",
			},
		}
	}

	refreshTokenHash := utils.HashToken(oldToken)

	wg := sync.WaitGroup{}
	var refreshTokenErr error
	var userErr error
	var refreshToken *authdomain.RefreshToken
	var user usersdomain.User

	wg.Go(func() {
		refreshToken, refreshTokenErr = authSrv.refreshTokenRepo.GetRefreshTokenByTokenHashAndUserID(ctx, refreshTokenHash, userID)
	})
	wg.Go(func() {
		user, userErr = authSrv.userRepo.GetUserByID(ctx, userID)
	})

	wg.Wait()

	if refreshTokenErr != nil {
		if errors.Is(refreshTokenErr, pgx.ErrNoRows) {
			return nil, &errs.AppError{
				Code:    errs.CodeUnauthorized,
				Message: "invalid refresh token",
				Err:     err,
				Details: nil,
			}
		}
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to get refresh token",
			Err:     err,
			Details: nil,
		}
	}

	if refreshToken.IsRevoked {
		return nil, &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "refresh token has been revoked",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has been revoked",
			},
		}
	}

	if userErr != nil {
		if errors.Is(userErr, pgx.ErrNoRows) {
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

	accessToken, err := authSrv.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Minute*15))
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}
	accessTokenHash := utils.HashToken(accessToken)
	rawID, err := uuid.NewV4()
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}
	accessTokenEntity := authdomain.Token{
		ID:             pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:         user.ID,
		TokenHash:      accessTokenHash,
		ExpiresAt:      time.Now().Add(time.Minute * 15),
		CreatedAt:      time.Now(),
		IsRevoked:      false,
		RevokedAt:      sql.NullTime{},
		RefreshTokenID: refreshToken.ID,
	}

	err = authSrv.tokenRepo.InsertToken(ctx, &accessTokenEntity)
	if err != nil {
		return nil, &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to insert access token",
			Err:     err,
			Details: nil,
		}
	}

	return &RefreshResult{
		AccessToken: accessToken,
	}, nil
}

func (authSrv *AuthService) Logout(ctx context.Context, input LogoutInput) *errs.AppError {
	if err := authSrv.validateLogoutRequest(input); err != nil {
		return err
	}

	refreshToken := strings.TrimSpace(input.RefreshToken)

	parsedRefreshToken, err := authSrv.jwt.ParseToken(refreshToken)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to parse refresh token",
			Err:     err,
			Details: nil,
		}
	}
	userID, ok := parsedRefreshToken["userId"].(string)
	if !ok || userID == "" {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to fetch user id from the context",
			Err:     err,
			Details: nil,
		}
	}

	expTime, err := parsedRefreshToken.GetExpirationTime()
	if err != nil || expTime == nil {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to fetch expiration time from the refresh token",
			Err:     err,
			Details: nil,
		}
	}

	if time.Now().After(expTime.Time) {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "refresh token has expired",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has expired",
			},
		}
	}

	refreshTokenHash := utils.HashToken(refreshToken)
	IsRefreshTokenRevoked, err := authSrv.refreshTokenRepo.IsRefreshTokenRevoked(ctx, refreshTokenHash, userID)

	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to check if refresh token is revoked",
			Err:     err,
			Details: nil,
		}
	}

	if IsRefreshTokenRevoked {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "refresh token has been revoked",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has been revoked",
			},
		}
	}

	err = authSrv.refreshTokenRepo.RevokeRefreshToken(ctx, refreshTokenHash, userID)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to revoke refresh token",
			Err:     err,
			Details: nil,
		}
	}

	return nil
}

func (authSrv *AuthService) LogoutAll(ctx context.Context, input LogoutInput) *errs.AppError {
	if err := authSrv.validateLogoutRequest(input); err != nil {
		return err
	}

	refreshToken := strings.TrimSpace(input.RefreshToken)

	parsedRefreshToken, err := authSrv.jwt.ParseToken(refreshToken)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to parse refresh token",
			Err:     err,
			Details: nil,
		}
	}
	userID, ok := parsedRefreshToken["userId"].(string)
	if !ok || userID == "" {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to fetch user id from the context",
			Err:     err,
			Details: nil,
		}
	}

	expTime, err := parsedRefreshToken.GetExpirationTime()
	if err != nil || expTime == nil {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "failed to fetch expiration time from the refresh token",
			Err:     err,
			Details: nil,
		}
	}

	// TODO: introduce transaction here between refresh token and token
	wg := sync.WaitGroup{}
	var err01 error
	var err02 error

	wg.Go(func() {
		err01 = authSrv.refreshTokenRepo.RevokeNonExpiredRefreshTokens(ctx, userID)
	})
	wg.Go(func() {
		err02 = authSrv.tokenRepo.RevokeNonExpiredTokens(ctx, userID)
	})

	wg.Wait()

	if err01 != nil || err02 != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to logout all",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "failed to logout all",
			},
		}
	}
	return nil

}

func (authSrv *AuthService) GetUserByID(ctx context.Context, id string) (*UserResult, *errs.AppError) {
	user, err := authSrv.userRepo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
			Details: map[string]string{
				"user": "failed to get user",
			},
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

	return &UserResult{
		ID:        user.ID.String(),
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Username:  user.Username,
	}, nil
}

func (authSrv *AuthService) ChangePassword(ctx context.Context, input ChangePasswordInput, userID string) *errs.AppError {
	if err := authSrv.validateChangePasswordRequest(input); err != nil {
		return err
	}
	user, err := authSrv.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeNotFound,
			Message: "user not found",
			Err:     err,
			Details: nil,
		}
	}
	newPasswordHash, err := utils.HashPassword(input.NewPassword)
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to hash new password",
			Err:     err,
			Details: nil,
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.OldPassword))
	if err != nil {
		return &errs.AppError{
			Code:    errs.CodeUnauthorized,
			Message: "old password is invalid",
			Err:     nil,
			Details: nil,
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.NewPassword))
	if err == nil {
		return &errs.AppError{
			Code:    errs.CodeValidation,
			Message: "new password must be different from the old password",
			Err:     nil,
			Details: nil,
		}
	}
	err = authSrv.userRepo.UpdateUserPassword(ctx, userID, newPasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &errs.AppError{
				Code:    errs.CodeNotFound,
				Message: "user not found",
				Err:     err,
				Details: nil,
			}
		}
		return &errs.AppError{
			Code:    errs.CodeInternal,
			Message: "failed to update user password",
			Err:     err,
			Details: nil,
		}
	}
	return nil
}

// private utils methods
func (authSrv *AuthService) validateRegisterRequest(req RegisterInput) *errs.AppError {
	errors := make(map[string]string)

	email := strings.TrimSpace(req.Email)
	username := strings.TrimSpace(req.Username)
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)

	if email == "" {
		errors["email"] = "email is required"
	} else if !isValidEmail(email) {
		errors["email"] = "email must be a valid email address"
	}

	if username == "" {
		errors["username"] = "username is required"
	} else {
		if len(username) < 3 || len(username) > 32 {
			errors["username"] = "username must be between 3 and 32 characters"
		} else if !usernamePattern.MatchString(username) {
			errors["username"] = "username can only contain letters, numbers, and underscores"
		}
	}

	if firstName == "" {
		errors["first_name"] = "first name is required"
	} else if len(firstName) > 50 {
		errors["first_name"] = "first name must not exceed 50 characters"
	}

	if lastName == "" {
		errors["last_name"] = "last name is required"
	} else if len(lastName) > 50 {
		errors["last_name"] = "last name must not exceed 50 characters"
	}

	if strings.TrimSpace(req.Password) == "" {
		errors["password"] = "password is required"
	} else if !authSrv.isPasswordValid(req.Password) {
		errors["password"] = "password must be between 8 and 72 characters"
	}

	if len(errors) > 0 {
		return &errs.AppError{
			Code:    errs.CodeValidation,
			Message: "invalid register request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (authSrv *AuthService) validateLoginRequest(req LoginInput) *errs.AppError {
	errors := make(map[string]string)

	email := strings.TrimSpace(req.Email)
	password := strings.TrimSpace(req.Password)

	if email == "" {
		errors["email"] = "email is required"
	} else if !isValidEmail(email) {
		errors["email"] = "email must be a valid email address"
	}

	if password == "" {
		errors["password"] = "password is required"
	}

	if len(errors) > 0 {
		return &errs.AppError{
			Code:    errs.CodeValidation,
			Message: "invalid login request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (authSrv *AuthService) validateRefreshRequest(req RefreshInput) *errs.AppError {
	errors := make(map[string]string)

	refreshToken := strings.TrimSpace(req.RefreshToken)

	if refreshToken == "" {
		errors["refresh_token"] = "refresh token is required"
	}

	if len(errors) > 0 {
		return &errs.AppError{
			Code:    errs.CodeValidation,
			Message: "invalid refresh request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (authSrv *AuthService) validateLogoutRequest(req LogoutInput) *errs.AppError {
	errors := make(map[string]string)

	refreshToken := strings.TrimSpace(req.RefreshToken)

	if refreshToken == "" {
		errors["refresh_token"] = "refresh token is required"
	}

	if len(errors) > 0 {
		return &errs.AppError{
			Code:    errs.CodeValidation,
			Message: "invalid logout request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (authSrv *AuthService) validateChangePasswordRequest(req ChangePasswordInput) *errs.AppError {
	errors := make(map[string]string)

	if req.OldPassword == "" {
		errors["old_password"] = "old password is required"
	}

	if req.NewPassword == "" {
		errors["new_password"] = "new password is required"
	} else if !authSrv.isPasswordValid(req.NewPassword) {
		errors["new_password"] = "new password must be between 8 and 72 characters"
	}

	if len(errors) > 0 {
		return &errs.AppError{
			Code:    errs.CodeValidation,
			Message: "invalid change password request",
			Err:     nil,
			Details: errors,
		}
	}
	return nil
}
func isValidEmail(email string) bool {
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	return parsed.Address == email
}

func (authSrv *AuthService) isPasswordValid(password string) bool {
	if len(password) < 8 || len(password) > 72 {
		return false
	}
	return true
}
