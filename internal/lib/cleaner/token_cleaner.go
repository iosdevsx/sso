package cleaner

import (
	"context"
	"log/slog"
	"time"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/lib/sl"
)

const cleanTimeout = time.Second * 15

type RefreshTokenCleaner interface {
	DeleteExpiredRefreshTokens(ctx context.Context, retention time.Duration) (int64, error)
}

type TokenCleanWorker struct {
	log       *slog.Logger
	cleaner   RefreshTokenCleaner
	interval  time.Duration
	retention time.Duration
}

func NewTokenCleaner(log *slog.Logger, cleaner RefreshTokenCleaner, interval time.Duration, retention time.Duration) *TokenCleanWorker {
	return &TokenCleanWorker{
		log:       log,
		cleaner:   cleaner,
		interval:  interval,
		retention: retention,
	}
}

func (w *TokenCleanWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.log.Info("cleaner stop")
			return
		case <-ticker.C:
			w.clean(ctx)
		}
	}
}

func (w *TokenCleanWorker) clean(ctx context.Context) error {
	const operation = "cleaner.clean"
	cleanCtx, cleanCancel := context.WithTimeout(ctx, cleanTimeout)
	defer cleanCancel()
	rowsAffected, err := w.cleaner.DeleteExpiredRefreshTokens(cleanCtx, w.retention)
	if err != nil {
		w.log.Error("clean error", sl.Err(err))
		return errs.Wrap(operation, err)
	}
	if rowsAffected > 0 {
		w.log.Info("clean:", "tokens", rowsAffected)
	} else {
		w.log.Debug("clean zero tokens")
	}

	return nil
}
