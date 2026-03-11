package main

import (
	"context"
	"go-auth-micro-service/internal/config"
	"go-auth-micro-service/internal/db"
)

func main() {
	cfg := config.Config{}
	err := cfg.Load()
	if err != nil {
		panic(err)
	}
	db.NewPostgres(context.Background(), cfg)
	
}
