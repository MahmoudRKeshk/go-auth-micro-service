package main

import (
	"context"
	"go-auth-micro-service/internal/config"
	"go-auth-micro-service/internal/db"
	"go-auth-micro-service/internal/handlers"
	"go-auth-micro-service/internal/repositories/postgres"
	"go-auth-micro-service/internal/routes"
	"go-auth-micro-service/internal/services"
	"go-auth-micro-service/pkg/security"
	"log"
	"net/http"
	"go-auth-micro-service/internal/middlewares"
)

func main() {
	cfg := config.Config{}
	err := cfg.Load()
	if err != nil {
		panic(err)
	}

	postgresDB := db.NewPostgres(context.Background(), cfg)
	defer postgresDB.Pool.Close()

	userRepo := postgres.NewUserRepository(postgresDB)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(postgresDB)
	tokenRepo := postgres.NewTokenRepository(postgresDB)
	JwtService := security.NewJwtService(cfg.GetJwtSecret())
	userService := services.NewUserService(userRepo, refreshTokenRepo, tokenRepo, *JwtService)
	middlewares := middlewares.NewMiddlewares(JwtService, tokenRepo)

	authHandler := handlers.NewAuthHandler(userService, middlewares)
	mux := http.NewServeMux()

	routes.RegisterRoutes(mux, authHandler, middlewares)

	serverAddr := cfg.GetServerPort()
	log.Printf("server listening on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatal(err)
	}
}
