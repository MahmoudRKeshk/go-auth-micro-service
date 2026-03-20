package services

import (
	"context"
	"database/sql"
	"errors"
	"go-auth-micro-service/internal/apperrors"
	"go-auth-micro-service/internal/models"
	"go-auth-micro-service/internal/repositories"
	"go-auth-micro-service/pkg/security"
	"go-auth-micro-service/pkg/utils"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"fmt"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type AuthService struct {
	userRepo         repositories.UserRepository
	refreshTokenRepo repositories.RefreshTokenRepository
	tokenRepo        repositories.TokenRepository
	jwt              security.JwtService
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func NewUserService(ur repositories.UserRepository, refreshTokenRepo repositories.RefreshTokenRepository, tokenRepo repositories.TokenRepository, jwt security.JwtService) *AuthService {
	return &AuthService{userRepo: ur, refreshTokenRepo: refreshTokenRepo, tokenRepo: tokenRepo, jwt: jwt}
}

func (u *AuthService) CreateUser(ctx context.Context, input RegisterInput) *apperrors.AppError {
	if err := u.validateRegisterRequest(input); err != nil {
		return err
	}

	email := strings.TrimSpace(input.Email)
	username := strings.TrimSpace(input.Username)
	firstName := strings.TrimSpace(input.FirstName)
	lastName := strings.TrimSpace(input.LastName)

	// Check if email already exists
	emailExists, err := u.userRepo.EmailExists(ctx, email)
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to create user: failed to check if email exists",
			Err:     err,
			Details: nil,
		}
	}
	if emailExists {
		return &apperrors.AppError{
			Code:    apperrors.CodeConflict,
			Message: "email already exists: email is already registered",
			Err:     nil,
			Details: map[string]string{"email": "email is already registered"},
		}
	}

	// Check if username already exists
	usernameExists, err := u.userRepo.UsernameExists(ctx, username)
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to create user",
			Err:     err,
			Details: nil,
		}
	}
	if usernameExists {
		return &apperrors.AppError{
			Code:    apperrors.CodeConflict,
			Message: "username already exists: username is already taken",
			Err:     nil,
			Details: map[string]string{"username": "username is already taken"},
		}
	}

	passwordHash, err := utils.HashPassword(input.Password)
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to create user: failed to hash password",
			Err:     err,
			Details: nil,
		}
	}

	rawID, err := uuid.NewV4()
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to create user: failed to generate user id",
			Err:     err,
			Details: nil,
		}
	}

	user := &models.User{
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

	createdUser, err := u.userRepo.CreateUser(ctx, user)
	if err != nil {
		fmt.Printf("failed to create user: %v\n", err)
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to create user: failed to create user",
			Err:     err,
			Details: nil,
		}
	}

	_ = createdUser

	return nil
}

func (u *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, *apperrors.AppError) {
	if err := u.validateLoginRequest(input); err != nil {
		return nil, err
	}

	email := strings.TrimSpace(input.Email)
	password := strings.TrimSpace(input.Password)

	user, err := u.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeNotFound,
			Message: "user not found: email not found",
			Err:     err,
			Details: map[string]string{
				"email": "email not found",
			},
		}
	}

	isPasswordValid := utils.CheckPasswordHash(password, user.PasswordHash)
	if !isPasswordValid {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "invalid credentials: invalid password",
			Err:     nil,
			Details: nil,
		}
	}

	refreshToken, err := u.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Hour*24*7))
	accessToken, err := u.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Minute*15))
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}

	rawID, err := uuid.NewV4()
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}

	refreshTokenHash := utils.HashToken(refreshToken)
	accessTokenHash := utils.HashToken(accessToken)

	refreshTokenEntity := &models.RefreshToken{
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
	refreshTokenEntity, err = u.refreshTokenRepo.InsertRefreshToken(ctx, refreshTokenEntity)
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to insert refresh token",
			Err:     err,
			Details: nil,
		}
	}

	tokenEntity := models.Token{
		ID:             pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:         user.ID,
		TokenHash:      accessTokenHash,
		ExpiresAt:      time.Now().Add(time.Minute * 15),
		CreatedAt:      time.Now(),
		IsRevoked:      false,
		RevokedAt:      sql.NullTime{},
		RefreshTokenID: refreshTokenEntity.ID,
	}

	err = u.tokenRepo.InsertToken(ctx, &tokenEntity)
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
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

func (u *AuthService) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, *apperrors.AppError) {
	if err := u.validateRefreshRequest(input); err != nil {
		return nil, err
	}

	oldToken := strings.TrimSpace(input.RefreshToken)

	parsedRefreshToken, err := u.jwt.ParseToken(oldToken)
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to parse refresh token",
			Err:     err,
			Details: nil,
		}
	}
	userID, ok := parsedRefreshToken["userId"].(string)
	if !ok || userID == "" {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to fetch user id from the context",
			Err:     err,
			Details: nil,
		}
	}

	expTime, err := parsedRefreshToken.GetExpirationTime()
	if err != nil || expTime == nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to fetch expiration time from the refresh token",
			Err:     err,
			Details: nil,
		}
	}

	if time.Now().After(expTime.Time) {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
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
	var refreshToken *models.RefreshToken
	var user models.User

	wg.Go(func() {
		refreshToken, refreshTokenErr = u.refreshTokenRepo.GetRefreshTokenByTokenHashAndUserID(ctx, refreshTokenHash, userID)
	})
	wg.Go(func() {
		user, userErr = u.userRepo.GetUserByID(ctx, userID)
	})

	wg.Wait()

	if refreshTokenErr != nil {
		if errors.Is(refreshTokenErr, pgx.ErrNoRows) {
			return nil, &apperrors.AppError{
				Code:    apperrors.CodeUnauthorized,
				Message: "invalid refresh token",
				Err:     err,
				Details: nil,
			}
		}
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to get refresh token",
			Err:     err,
			Details: nil,
		}
	}

	if refreshToken.IsRevoked {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "refresh token has been revoked",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has been revoked",
			},
		}
	}

	if userErr != nil {
		if errors.Is(userErr, pgx.ErrNoRows) {
			return nil, &apperrors.AppError{
				Code:    apperrors.CodeNotFound,
				Message: "user not found",
				Err:     err,
				Details: nil,
			}
		}
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to get user",
			Err:     err,
			Details: nil,
		}
	}
	if user.IsActive == false {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeNotFound,
			Message: "user not found",
			Err:     err,
			Details: nil,
		}
	}

	accessToken, err := u.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Minute*15))
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}
	accessTokenHash := utils.HashToken(accessToken)
	rawID, err := uuid.NewV4()
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to generate access token",
			Err:     err,
			Details: nil,
		}
	}
	accessTokenEntity := models.Token{
		ID:             pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:         user.ID,
		TokenHash:      accessTokenHash,
		ExpiresAt:      time.Now().Add(time.Minute * 15),
		CreatedAt:      time.Now(),
		IsRevoked:      false,
		RevokedAt:      sql.NullTime{},
		RefreshTokenID: refreshToken.ID,
	}

	err = u.tokenRepo.InsertToken(ctx, &accessTokenEntity)
	if err != nil {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to insert access token",
			Err:     err,
			Details: nil,
		}
	}

	return &RefreshResult{
		AccessToken: accessToken,
	}, nil
}

func (u *AuthService) Logout(ctx context.Context, input LogoutInput) *apperrors.AppError {
	if err := u.validateLogoutRequest(input); err != nil {
		return err
	}

	refreshToken := strings.TrimSpace(input.RefreshToken)

	parsedRefreshToken, err := u.jwt.ParseToken(refreshToken)
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to parse refresh token",
			Err:     err,
			Details: nil,
		}
	}
	userID, ok := parsedRefreshToken["userId"].(string)
	if !ok || userID == "" {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to fetch user id from the context",
			Err:     err,
			Details: nil,
		}
	}

	expTime, err := parsedRefreshToken.GetExpirationTime()
	if err != nil || expTime == nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to fetch expiration time from the refresh token",
			Err:     err,
			Details: nil,
		}
	}

	if time.Now().After(expTime.Time) {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "refresh token has expired",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has expired",
			},
		}
	}

	refreshTokenHash := utils.HashToken(refreshToken)
	IsRefreshTokenRevoked, err := u.refreshTokenRepo.IsRefreshTokenRevoked(ctx, refreshTokenHash, userID)

	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to check if refresh token is revoked",
			Err:     err,
			Details: nil,
		}
	}

	if IsRefreshTokenRevoked {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "refresh token has been revoked",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "refresh token has been revoked",
			},
		}
	}

	err = u.refreshTokenRepo.RevokeRefreshToken(ctx, refreshTokenHash, userID)
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to revoke refresh token",
			Err:     err,
			Details: nil,
		}
	}

	return nil
}

func (u *AuthService) LogoutAll(ctx context.Context, input LogoutInput) *apperrors.AppError {
	if err := u.validateLogoutRequest(input); err != nil {
		return err
	}

	refreshToken := strings.TrimSpace(input.RefreshToken)

	parsedRefreshToken, err := u.jwt.ParseToken(refreshToken)
	if err != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to parse refresh token",
			Err:     err,
			Details: nil,
		}
	}
	userID, ok := parsedRefreshToken["userId"].(string)
	if !ok || userID == "" {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
			Message: "failed to fetch user id from the context",
			Err:     err,
			Details: nil,
		}
	}

	expTime, err := parsedRefreshToken.GetExpirationTime()
	if err != nil || expTime == nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeUnauthorized,
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
		err01 = u.refreshTokenRepo.RevokeNonExpiredRefreshTokens(ctx, userID)
	})
	wg.Go(func() {
		err02 = u.tokenRepo.RevokeNonExpiredTokens(ctx, userID)
	})

	wg.Wait()

	if err01 != nil || err02 != nil {
		return &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to logout all",
			Err:     err,
			Details: map[string]string{
				"refresh_token": "failed to logout all",
			},
		}
	}
	return nil

}

func (u *AuthService) GetUserByID(ctx context.Context, id string) (*UserResult, *apperrors.AppError) {
	user, err := u.userRepo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &apperrors.AppError{
				Code:    apperrors.CodeNotFound,
				Message: "user not found",
				Err:     err,
				Details: nil,
			}
		}
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeInternal,
			Message: "failed to get user",
			Err:     err,
			Details: map[string]string{
				"user": "failed to get user",
			},
		}
	}

	if user.IsActive == false {
		return nil, &apperrors.AppError{
			Code:    apperrors.CodeNotFound,
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

// private utils methods
func (u *AuthService) validateRegisterRequest(req RegisterInput) *apperrors.AppError {
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
	} else if len(req.Password) < 8 || len(req.Password) > 72 {
		errors["password"] = "password must be between 8 and 72 characters"
	}

	if len(errors) > 0 {
		return &apperrors.AppError{
			Code:    apperrors.CodeValidation,
			Message: "invalid register request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (u *AuthService) validateLoginRequest(req LoginInput) *apperrors.AppError {
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
		return &apperrors.AppError{
			Code:    apperrors.CodeValidation,
			Message: "invalid login request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (u *AuthService) validateRefreshRequest(req RefreshInput) *apperrors.AppError {
	errors := make(map[string]string)

	refreshToken := strings.TrimSpace(req.RefreshToken)

	if refreshToken == "" {
		errors["refresh_token"] = "refresh token is required"
	}

	if len(errors) > 0 {
		return &apperrors.AppError{
			Code:    apperrors.CodeValidation,
			Message: "invalid refresh request",
			Err:     nil,
			Details: errors,
		}
	}

	return nil
}

func (u *AuthService) validateLogoutRequest(req LogoutInput) *apperrors.AppError {
	errors := make(map[string]string)

	refreshToken := strings.TrimSpace(req.RefreshToken)

	if refreshToken == "" {
		errors["refresh_token"] = "refresh token is required"
	}

	if len(errors) > 0 {
		return &apperrors.AppError{
			Code:    apperrors.CodeValidation,
			Message: "invalid logout request",
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
