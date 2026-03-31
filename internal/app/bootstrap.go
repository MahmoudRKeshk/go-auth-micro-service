package app

import (
	"context"
	authapi "go-auth-micro-service/internal/auth/api"
	authpostgres "go-auth-micro-service/internal/auth/repository/postgres"
	authservice "go-auth-micro-service/internal/auth/service"
	"go-auth-micro-service/internal/platform/config"
	"go-auth-micro-service/internal/platform/db"
	"go-auth-micro-service/internal/platform/middlewares"
	"go-auth-micro-service/internal/platform/security"
	usersapi "go-auth-micro-service/internal/users/api"
	userspostgres "go-auth-micro-service/internal/users/repository/postgres"
	userservice "go-auth-micro-service/internal/users/service"
	"log"
	"net/http"
)

func Run() {
	cfg := config.Config{}
	err := cfg.Load()
	if err != nil {
		panic(err)
	}

	postgresDB := db.NewPostgres(context.Background(), cfg)
	defer postgresDB.Pool.Close()

	// repositories
	tokenRepo := authpostgres.NewTokenRepository(postgresDB)
	refreshTokenRepo := authpostgres.NewRefreshTokenRepository(postgresDB)
	userRepo := userspostgres.NewUserRepository(postgresDB)

	// services
	jwtService := security.NewJwtService(cfg.GetJwtSecret())
	userService := userservice.NewUserService(userRepo, tokenRepo, refreshTokenRepo, postgresDB)
	authService := authservice.NewAuthService(userRepo, refreshTokenRepo, tokenRepo, *jwtService, postgresDB)

	// middlewares
	authMiddleware := middlewares.NewAuthMiddlewares(jwtService, tokenRepo)

	// handlers
	userHandler := usersapi.NewUserHandler(userService)
	authHandler := authapi.NewAuthHandler(authService, authMiddleware)

	// routes
	mux := http.NewServeMux()
	usersapi.RegisterRoutes(mux, userHandler)
	authapi.RegisterRoutes(mux, authHandler, authMiddleware)

	// start server
	serverAddr := cfg.GetServerPort()
	log.Printf("server listening on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatal(err)
	}
}
