package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iosdevsx/sso/internal/domain/errs"
)

func TestService_Logout_Success(t *testing.T) {
	const raw = "raw-refresh-token"
	fake := &storageFake{consumeUserID: 8}
	service := newTestService(fake, &hasherFake{}, time.Hour, "s", time.Hour)

	err := service.Logout(context.Background(), raw)

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if fake.consumeCalls != 1 {
		t.Fatalf("Consume calls = %d, want 1", fake.consumeCalls)
	}
	if fake.gotConsumeHash != hashRefresh(raw) {
		t.Fatalf("Consume got %q, want hash of presented token", fake.gotConsumeHash)
	}
}

func TestService_Logout_UnknownTokenIsIdempotent(t *testing.T) {
	// повторный/чужой/протухший logout — не ошибка
	fake := &storageFake{consumeErr: errs.ErrRefreshTokenNotFound}
	service := newTestService(fake, &hasherFake{}, time.Hour, "s", time.Hour)

	if err := service.Logout(context.Background(), "already-dead"); err != nil {
		t.Fatalf("logout must be idempotent, got %v", err)
	}
}

func TestService_Logout_StorageFailure(t *testing.T) {
	// не смогли погасить — молчать нельзя
	fake := &storageFake{consumeErr: errors.New("db connection lost")}
	service := newTestService(fake, &hasherFake{}, time.Hour, "s", time.Hour)

	if err := service.Logout(context.Background(), "raw"); err == nil {
		t.Fatalf("expected error on storage failure, got nil")
	}
}
