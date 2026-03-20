package main

import (
	"context"
	"go-auth-micro-service/internal/auth/api"
	authpostgres "go-auth-micro-service/internal/auth/repository/postgres"
	"go-auth-micro-service/internal/auth/service"
	"go-auth-micro-service/internal/platform/config"
	"go-auth-micro-service/internal/platform/db"
	"go-auth-micro-service/internal/platform/middlewares"
	"go-auth-micro-service/internal/platform/security"
	userspostgres "go-auth-micro-service/internal/users/repository/postgres"
	"log"
	"net/http"
)

func main() {
	cfg := config.Config{}
	err := cfg.Load()
	if err != nil {
		panic(err)
	}

	postgresDB := db.NewPostgres(context.Background(), cfg)
	defer postgresDB.Pool.Close()

	userRepo := userspostgres.NewUserRepository(postgresDB)
	refreshTokenRepo := authpostgres.NewRefreshTokenRepository(postgresDB)
	tokenRepo := authpostgres.NewTokenRepository(postgresDB)
	JwtService := security.NewJwtService(cfg.GetJwtSecret())
	userService := service.NewUserService(userRepo, refreshTokenRepo, tokenRepo, *JwtService)
	authMiddleware := middlewares.NewMiddlewares(JwtService, tokenRepo)

	authHandler := api.NewAuthHandler(userService, authMiddleware)
	mux := http.NewServeMux()

	api.RegisterRoutes(mux, authHandler, authMiddleware)

	serverAddr := cfg.GetServerPort()
	log.Printf("server listening on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatal(err)
	}
}
