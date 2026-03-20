package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go-auth-micro-service/internal/platform/config"
)

type Postgres struct {
	Pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, cfg config.Config) *Postgres {
	pool, err := pgxpool.New(ctx, cfg.GetBURL())
	if err != nil {
		panic(err)
	}

	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()
	err = pool.Ping(pingCtx)

	if err != nil {
		panic(err)
	}

	return &Postgres{Pool: pool}
}