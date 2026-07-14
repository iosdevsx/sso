package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/iosdevsx/sso/internal/config"
	authgrpc "github.com/iosdevsx/sso/internal/grpc/auth"
	"github.com/iosdevsx/sso/internal/lib/hasher"
	"github.com/iosdevsx/sso/internal/lib/sl"
	authservice "github.com/iosdevsx/sso/internal/service/auth"
	"github.com/iosdevsx/sso/internal/service/providers"
	"github.com/iosdevsx/sso/internal/storage/migrations"
	"github.com/iosdevsx/sso/internal/storage/postgres"
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
	dbpool, err := setupStorage(ctx, cfg)
	if err != nil {
		logger.Error("db run failed", sl.Err(err))
		os.Exit(1)
	}
	defer dbpool.Close()

	logger.Info("Storage initialized", slog.String("env", cfg.Env))

	storage := postgres.NewStorage(dbpool)
	hasher := hasher.New()
	appProvider := providers.New()
	grpcServer := grpc.NewServer()
	service := authservice.NewService(logger, storage, hasher, appProvider, 0)

	authgrpc.Register(logger, grpcServer, service)
	reflection.Register(grpcServer)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))

	if err != nil {
		logger.Error("listener failed", sl.Err(err))
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

func setupStorage(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	dbUrl := cfg.DBServer.DatabaseURL()
	err := migrations.Run(dbUrl)

	if err != nil {
		return nil, fmt.Errorf("migrations run failed: %w", err)
	}

	dbConfig, err := pgxpool.ParseConfig(dbUrl)

	if err != nil {
		return nil, fmt.Errorf("parse config failed: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)

	if err != nil {
		return nil, fmt.Errorf("pool creation failed: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pool ping failed: %w", err)
	}

	return pool, nil
}
