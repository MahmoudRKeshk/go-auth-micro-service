package main

import (
	"context"
	"go-auth-micro-service/internal/config"
	"go-auth-micro-service/internal/db"
	"go-auth-micro-service/internal/handlers"
	"go-auth-micro-service/internal/repositories/postgres"
	"go-auth-micro-service/internal/routes"
	"go-auth-micro-service/internal/services"
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

	userRepo := postgres.NewUserRepository(postgresDB)
	userService := services.NewUserService(userRepo, cfg)
	authHandler := handlers.NewAuthHandler(userService)

	mux := http.NewServeMux()
	
	routes.RegisterRoutes(mux, authHandler)

	serverAddr := cfg.GetServerPort()
	log.Printf("server listening on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatal(err)
	}
}
