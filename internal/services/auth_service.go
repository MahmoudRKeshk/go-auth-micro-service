package services

import (
	"context"
	"database/sql"
	"go-auth-micro-service/internal/dtos/auth"
	"go-auth-micro-service/internal/dtos/common"
	"go-auth-micro-service/internal/models"
	"go-auth-micro-service/internal/repositories"
	"go-auth-micro-service/pkg/utils"
	"net/mail"
	"regexp"
	"strings"
	"time"

	gofrsuuid "github.com/gofrs/uuid"
	pgUUID "github.com/jackc/pgx/pgtype/ext/gofrs-uuid"
)

type UserService struct {
	repo repositories.UserRepository
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func NewUserService(ur repositories.UserRepository) *UserService {
	return &UserService{repo: ur}
}

func (u *UserService) CreateUser(ctx context.Context, req *auth.RegisterRequest) *common.ErrorResponse {
	if err := u.validateRegisterRequest(req); err != nil {
		return err
	}

	email := strings.TrimSpace(req.Email)
	username := strings.TrimSpace(req.Username)
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)

	// Check if email already exists
	emailExists, err := u.repo.EmailExists(ctx, email)
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
	usernameExists, err := u.repo.UsernameExists(ctx, username)
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: nil,
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
			Details: nil,
		}
	}

	rawID, err := gofrsuuid.NewV4()
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: nil,
		}
	}

	userID := pgUUID.UUID{}
	if err := userID.Set(rawID); err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: nil,
		}
	}

	user := &models.User{
		ID:           userID,
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

	createdUser, err := u.repo.CreateUser(ctx, user)
	if err != nil {
		return &common.ErrorResponse{
			Code:    "SERVER_ERROR",
			Message: "failed to create user",
			Details: nil,
		}
	}

	_ = createdUser

	return nil
}

// private utils methods
func (u *UserService) validateRegisterRequest(req *auth.RegisterRequest) *common.ErrorResponse {
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

func isValidEmail(email string) bool {
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	return parsed.Address == email
}
