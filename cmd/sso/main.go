package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/iosdevsx/sso/internal/config"
	"github.com/iosdevsx/sso/internal/domain/errs"
	authgrpc "github.com/iosdevsx/sso/internal/grpc/auth"
	"github.com/iosdevsx/sso/internal/lib/hasher"
	"github.com/iosdevsx/sso/internal/lib/sl"
	authservice "github.com/iosdevsx/sso/internal/service/auth"
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

	logger.Info("auth config", slog.Duration("ttl", cfg.Auth.TokenTTL), slog.Int("secret_len", len(cfg.Auth.TokenSecret)))

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
	grpcServer := grpc.NewServer()

	service := authservice.NewService(authservice.ServiceParams{
		Log:                  logger,
		UserStorage:          storage,
		TokenStorage:         storage,
		LoginAttemptsStorage: storage,
		PassHasher:           hasher,
		AuthParams: authservice.AuthParams{
			TokenTTL:        cfg.Auth.TokenTTL,
			TokenSecret:     cfg.Auth.TokenSecret,
			RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
			MaxAttempts:     cfg.Auth.MaxAttempts,
			LockDuration:    cfg.Auth.LockoutDuration,
		},
	})

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
	const (
		migration    = "operation.migrations.run"
		parseConfig  = "operation.config.parse"
		poolCreation = "operation.pool.create"
		poolPing     = "operation.pool.ping"
	)
	dbUrl := cfg.DBServer.DatabaseURL()
	err := migrations.Run(dbUrl)

	if err != nil {
		return nil, errs.Wrap(migration, err)
	}

	dbConfig, err := pgxpool.ParseConfig(dbUrl)

	if err != nil {
		return nil, errs.Wrap(parseConfig, err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)

	if err != nil {
		return nil, errs.Wrap(poolCreation, err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errs.Wrap(poolPing, err)
	}

	return pool, nil
}
