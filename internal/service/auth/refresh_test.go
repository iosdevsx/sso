package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/iosdevsx/sso/internal/domain/errs"
)

func TestService_Refresh_Success(t *testing.T) {
	//Arrange
	const secret = "test-secret"
	const refreshTTL = 30 * 24 * time.Hour
	const oldRaw = "old-raw-refresh-token"
	fake := &storageFake{rotateUserID: 8}
	hasher := &hasherFake{}
	service := newTestService(fake, hasher, time.Hour, secret, refreshTTL)

	//Act
	tokens, err := service.Refresh(context.Background(), oldRaw)

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if fake.rotateCalls != 1 {
		t.Fatalf("Rotate calls = %d, want 1", fake.rotateCalls)
	}

	// ротация получила hash предъявленного токена, не raw
	if fake.gotRotateOldHash != hashRefresh(oldRaw) {
		t.Fatalf("Rotate got old %q, want hash of presented token", fake.gotRotateOldHash)
	}

	// новый refresh существует, отличается от старого,
	// в storage ушёл его hash, а не raw
	if tokens.RefreshToken == "" || tokens.RefreshToken == oldRaw {
		t.Fatalf("refresh token not rotated: %q", tokens.RefreshToken)
	}
	if fake.gotRotateNewHash != hashRefresh(tokens.RefreshToken) {
		t.Fatalf("stored hash does not match returned raw token")
	}

	// expires_at ≈ now + refreshTTL
	wantExp := time.Now().Add(refreshTTL)
	if d := fake.gotRotateExp.Sub(wantExp); d < -5*time.Second || d > 5*time.Second {
		t.Fatalf("expires_at = %v, want ≈ %v", fake.gotRotateExp, wantExp)
	}

	// access-токен валиден и выписан нужному юзеру
	parsed, err := jwtlib.Parse(
		tokens.AccessToken,
		func(t *jwtlib.Token) (any, error) { return []byte(secret), nil },
		jwtlib.WithValidMethods([]string{"HS256"}),
	)
	if err != nil || !parsed.Valid {
		t.Fatalf("access token does not parse/verify: %v", err)
	}
	claims := parsed.Claims.(jwtlib.MapClaims)
	if sub, ok := claims["sub"].(float64); !ok || int64(sub) != 8 {
		t.Fatalf("claim sub = %v, want 8", claims["sub"])
	}
}

func TestService_Refresh_DeadToken(t *testing.T) {
	// протухший, погашенный и неизвестный токены storage отдаёт одинаково —
	// сервис обязан превратить это в ErrInvalidRefreshToken
	fake := &storageFake{rotateErr: errs.ErrRefreshTokenNotFound}
	service := newTestService(fake, &hasherFake{}, time.Hour, "s", time.Hour)

	tokens, err := service.Refresh(context.Background(), "whatever")

	if !errors.Is(err, errs.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken", err)
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Fatalf("tokens must be empty on error, got %+v", tokens)
	}
}

func TestService_Refresh_StorageFailureIsNotAuthError(t *testing.T) {
	// сбой хранилища не должен маскироваться под invalid token:
	// клиент на Unauthenticated сотрёт сессию
	fake := &storageFake{rotateErr: errors.New("db connection lost")}
	service := newTestService(fake, &hasherFake{}, time.Hour, "s", time.Hour)

	_, err := service.Refresh(context.Background(), "whatever")

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if errors.Is(err, errs.ErrInvalidRefreshToken) {
		t.Fatalf("storage failure must not look like invalid token: %v", err)
	}
}
