package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/iosdevsx/sso/internal/config"
	"github.com/iosdevsx/sso/internal/domain/errs"
	authgrpc "github.com/iosdevsx/sso/internal/grpc/auth"
	"github.com/iosdevsx/sso/internal/lib/cleaner"
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.MustLoad()

	logger := setupLogger(cfg.Env)
	logger.Info("starting sso", slog.String("env", cfg.Env))
	logger.Debug("debug messages are enabled")

	logger.Info("auth config", slog.Duration("ttl", cfg.Auth.TokenTTL), slog.Int("secret_len", len(cfg.Auth.TokenSecret)))

	// Initialize storage
	storage, dbpool, err := setupStorage(ctx, logger, cfg)
	if err != nil {
		logger.Error("db run failed", sl.Err(err))
		os.Exit(1)
	}
	defer dbpool.Close()

	cleaner := cleaner.NewTokenCleaner(
		logger,
		storage,
		cfg.Cleaner.Interval,
		cfg.Cleaner.Retention,
	)

	service := authservice.NewService(authservice.ServiceParams{
		Log:                  logger,
		UserStorage:          storage,
		TokenStorage:         storage,
		LoginAttemptsStorage: storage,
		PassHasher:           hasher.New(),
		AuthParams: authservice.AuthParams{
			TokenTTL:        cfg.Auth.TokenTTL,
			TokenSecret:     cfg.Auth.TokenSecret,
			RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
			MaxAttempts:     cfg.Auth.MaxAttempts,
			LockDuration:    cfg.Auth.LockoutDuration,
		},
	})

	grpcServer := grpc.NewServer()
	authgrpc.Register(logger, grpcServer, service)
	reflection.Register(grpcServer)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))

	var wg sync.WaitGroup

	wg.Go(func() {
		cleaner.Run(ctx)
	})

	if err != nil {
		logger.Error("listener failed", sl.Err(err))
		os.Exit(1)
	}

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			logger.Error("grpc server failed", sl.Err(err))
		}
	}()

	<-ctx.Done()
	logger.Info("shutdow received")

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("grpc shutdown done")
	case <-time.After(15 * time.Second):
		logger.Warn("forcing stop")
		grpcServer.Stop()
	}

	wg.Wait()
	logger.Info("shutdown complete")
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

func setupStorage(ctx context.Context, logger *slog.Logger, cfg *config.Config) (*postgres.Storage, *pgxpool.Pool, error) {
	const (
		migration    = "operation.migrations.run"
		parseConfig  = "operation.config.parse"
		poolCreation = "operation.pool.create"
		poolPing     = "operation.pool.ping"
	)
	dbUrl := cfg.DBServer.DatabaseURL()
	err := migrations.Run(dbUrl)

	if err != nil {
		return nil, nil, errs.Wrap(migration, err)
	}

	dbConfig, err := pgxpool.ParseConfig(dbUrl)

	if err != nil {
		return nil, nil, errs.Wrap(parseConfig, err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)

	if err != nil {
		return nil, nil, errs.Wrap(poolCreation, err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, errs.Wrap(poolPing, err)
	}

	logger.Info("Storage initialized", slog.String("env", cfg.Env))
	storage := postgres.NewStorage(pool)
	return storage, pool, nil
}
