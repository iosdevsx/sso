package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/iosdevsx/sso/internal/config"
	"github.com/iosdevsx/sso/internal/grpc/auth"
	"github.com/iosdevsx/sso/internal/storage/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	local = "local"
	dev   = "dev"
	prod  = "prod"
)

func main() {
	cfg := config.MustLoad()
	ctx := context.Background()

	logger := setupLogger(cfg.Env)
	logger.Info("starting sso", slog.String("env", cfg.Env))
	logger.Debug("debug messages are enabled")

	// Initialize storage
	dbpool, err := setupStorage(logger, ctx, cfg)
	if err != nil {
		logger.Error("db run failed", "error", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	logger.Info("Storage initialized", slog.String("env", cfg.Env))

	grpcServer := grpc.NewServer()
	auth.Register(grpcServer, nil)
	reflection.Register(grpcServer)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))

	if err != nil {
		logger.Error("listener failed", "error", err)
		os.Exit(1)
	}

	grpcServer.Serve(listener)
}

func setupLogger(env string) *slog.Logger {
	var logger *slog.Logger
	switch env {
	case local:
		logger = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case dev:
		logger = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case prod:
		logger = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	default:
		logger = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	}
	return logger
}

func setupStorage(log *slog.Logger, ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	dbUrl := cfg.DBServer.DatabaseURL()
	log.Info(dbUrl)
	err := migrations.Run(dbUrl)

	if err != nil {
		return nil, err
	}

	dbConfig, err := pgxpool.ParseConfig(dbUrl)

	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)

	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}

	return pool, nil
}
