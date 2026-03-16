package services

import (
	"context"
	"database/sql"
	"go-auth-micro-service/internal/dtos/common"
	"go-auth-micro-service/internal/models"
	"go-auth-micro-service/internal/repositories"
	"go-auth-micro-service/pkg/security"
	"go-auth-micro-service/pkg/utils"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"fmt"
	"go-auth-micro-service/internal/dtos"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
)

type UserService struct {
	userRepo         repositories.UserRepository
	refreshTokenRepo repositories.RefreshTokenRepository
	tokenRepo        repositories.TokenRepository
	jwt              security.JwtService
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func NewUserService(ur repositories.UserRepository, refreshTokenRepo repositories.RefreshTokenRepository, tokenRepo repositories.TokenRepository, jwt security.JwtService) *UserService {
	return &UserService{userRepo: ur, refreshTokenRepo: refreshTokenRepo, tokenRepo: tokenRepo, jwt: jwt}
}

func (u *UserService) CreateUser(ctx context.Context, req *dtos.RegisterRequest) *common.ErrorResponse {
	if err := u.validateRegisterRequest(req); err != nil {
		return err
	}

	email := strings.TrimSpace(req.Email)
	username := strings.TrimSpace(req.Username)
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)

	// Check if email already exists
	emailExists, err := u.userRepo.EmailExists(ctx, email)
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: nil,
		}
	}
	if emailExists {
		return &common.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "email already exists",
			Details: map[string]string{
				"email": "email is already registered",
			},
		}
	}

	// Check if username already exists
	usernameExists, err := u.userRepo.UsernameExists(ctx, username)
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: map[string]string{
				"username": "username is already taken",
			},
		}
	}
	if usernameExists {
		return &common.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "username already exists",
			Details: map[string]string{
				"username": "username is already taken",
			},
		}
	}

	passwordHash, err := utils.HashPassword(req.Password)
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: map[string]string{
				"password": "failed to hash password",
			},
		}
	}

	rawID, err := uuid.NewV4()
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
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
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: map[string]string{
				"user": "failed to create user",
			},
		}
	}

	_ = createdUser

	return nil
}

func (u *UserService) Login(ctx context.Context, req *dtos.LoginRequest) (*dtos.LoginResponse, *common.ErrorResponse) {
	if err := u.validateLoginRequest(req); err != nil {
		return nil, err
	}

	email := strings.TrimSpace(req.Email)
	password := strings.TrimSpace(req.Password)

	user, err := u.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, &common.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "user not found",
			Details: map[string]string{
				"email": "email not found",
			},
		}
	}

	isPasswordValid := utils.CheckPasswordHash(password, user.PasswordHash)
	if !isPasswordValid {
		return nil, &common.ErrorResponse{
			Code:    "BAD_REQUEST",
			Message: "invalid credentials",
			Details: map[string]string{
				"request": "invalid credentials",
			},
		}
	}

	refreshToken, err := u.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Hour*24*7))
	accessToken, err := u.jwt.GenerateToken(user.ID.String(), user.Username, time.Now().Add(time.Minute*15))
	if err != nil {
		return nil, &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to login",
			Details: map[string]string{
				"request": "failed to generate tokens",
			},
		}
	}

	rawID, err := uuid.NewV4()
	if err != nil {
		return nil, &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: nil,
		}
	}

	refreshTokenHash := utils.HashToken(refreshToken)
	accessTokenHash := utils.HashToken(accessToken)

	refreshTokenEntity := models.RefreshToken{
		ID:         pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:     user.ID,
		TokenHash:  refreshTokenHash,
		ExpiresAt:  time.Now().Add(time.Hour * 24 * 7),
		IsRevoked:  false,
		RevokedAt:  sql.NullTime{},
		LastUsedAt: sql.NullTime{},
		CreatedAt:  time.Now(),
	}

	tokenEntity := models.Token{
		ID:        pgtype.UUID{Bytes: rawID, Valid: true},
		UserID:    user.ID,
		TokenHash: accessTokenHash,
		ExpiresAt: time.Now().Add(time.Minute * 15),
		CreatedAt: time.Now(),
		IsRevoked: false,
		RevokedAt: sql.NullTime{},
	}

	wg := sync.WaitGroup{}
	var err01 error
	var err02 error

	wg.Go(func() {
		err01 = u.refreshTokenRepo.InsertRefreshToken(ctx, &refreshTokenEntity)
	})
	wg.Go(func() {
		err02 = u.tokenRepo.InsertToken(ctx, &tokenEntity)
	})

	wg.Wait()

	if err01 != nil || err02 != nil {
		return nil, &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create login",
			Details: nil,
		}
	}
	return &dtos.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// private utils methods
func (u *UserService) validateRegisterRequest(req *dtos.RegisterRequest) *common.ErrorResponse {
	if req == nil {
		return &common.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "invalid register request",
			Details: map[string]string{
				"request": "request body is required",
			},
		}
	}

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

	if req.Password == "" {
		errors["password"] = "password is required"
	} else if len(req.Password) < 8 || len(req.Password) > 72 {
		errors["password"] = "password must be between 8 and 72 characters"
	}

	if len(errors) > 0 {
		return &common.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "invalid register request",
			Details: errors,
		}
	}

	return nil
}

func (u *UserService) validateLoginRequest(req *dtos.LoginRequest) *common.ErrorResponse {
	if req == nil {
		return &common.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "invalid login request",
			Details: map[string]string{
				"request": "request body is required",
			},
		}
	}
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
		return &common.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "invalid login request",
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
