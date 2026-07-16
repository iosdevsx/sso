package cleaner

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type deleterFake struct {
	calls     atomic.Int64
	returnErr error
}

func (f *deleterFake) DeleteExpiredRefreshTokens(ctx context.Context, retention time.Duration) (int64, error) {
	f.calls.Add(1)
	return 0, f.returnErr
}

// Уборщик тикает и останавливается по отмене контекста, не подвисая.
func TestTokenCleanWorker_RunsAndStopsOnCancel(t *testing.T) {
	fake := &deleterFake{}
	w := NewTokenCleaner(slog.New(slog.DiscardHandler), fake, 10*time.Millisecond, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(stopped)
	}()

	// даём натикать несколько прогонов
	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case <-stopped:
		// вышел — хорошо
	case <-time.After(time.Second):
		t.Fatal("Run did not stop within 1s after cancel")
	}

	if got := fake.calls.Load(); got < 2 {
		t.Fatalf("cleanup calls = %d, want >= 2", got)
	}
}

// Ошибка одного прогона не убивает цикл — уборщик продолжает тикать.
func TestTokenCleanWorker_SurvivesCleanupError(t *testing.T) {
	fake := &deleterFake{returnErr: errors.New("db connection lost")}
	w := NewTokenCleaner(slog.New(slog.DiscardHandler), fake, 10*time.Millisecond, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(stopped)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop within 1s after cancel")
	}

	if got := fake.calls.Load(); got < 2 {
		t.Fatalf("cleanup calls = %d, want >= 2 (loop must survive errors)", got)
	}
}
