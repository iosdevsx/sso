package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/domain/models"
)

func TestService_Login_Success(t *testing.T) {
	//Arrange
	const secret = "test-secret"
	const ttl = time.Hour
	fake := &storageFake{
		getUserUser: models.User{ID: 8, Email: "test@test.com", PassHash: "stored-phc-hash"},
	}
	hasher := &hasherFake{verifyOK: true}
	service := newTestService(fake, hasher, ttl, secret, 30*24*time.Hour)

	//Act
	tokens, err := service.Login(context.Background(), "  Test@Test.COM  ", "correct-password-123")

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if fake.gotGetEmail != "test@test.com" {
		t.Fatalf("GetUser got %q, want canonical %q", fake.gotGetEmail, "test@test.com")
	}
	if hasher.gotVerifyHash != "stored-phc-hash" {
		t.Fatalf("Verify got hash %q, want stored hash", hasher.gotVerifyHash)
	}
	if hasher.hashCalls != 0 {
		t.Fatalf("Hash calls = %d, want 0: Login не должен хешировать (timing-заглушка — константа)", hasher.hashCalls)
	}

	// пара: refresh выдан, в storage ушёл его hash
	if tokens.RefreshToken == "" {
		t.Fatalf("refresh token is empty")
	}
	if fake.saveRefreshCalls != 1 {
		t.Fatalf("SaveRefreshToken calls = %d, want 1", fake.saveRefreshCalls)
	}
	if fake.gotRefreshHash != hashRefresh(tokens.RefreshToken) {
		t.Fatalf("stored hash does not match returned raw token")
	}
	if fake.gotRefreshUserID != 8 {
		t.Fatalf("refresh saved for user %d, want 8", fake.gotRefreshUserID)
	}

	parsed, err := jwtlib.Parse(
		tokens.AccessToken,
		func(t *jwtlib.Token) (any, error) { return []byte(secret), nil },
		jwtlib.WithValidMethods([]string{"HS256"}),
	)
	if err != nil || !parsed.Valid {
		t.Fatalf("token does not parse/verify: %v", err)
	}
	claims, ok := parsed.Claims.(jwtlib.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if sub, ok := claims["sub"].(float64); !ok || int64(sub) != 8 {
		t.Fatalf("claim sub = %v, want 8", claims["sub"])
	}
	if _, ok := claims["iat"]; !ok {
		t.Fatalf("claim iat is missing")
	}
	exp, ok := claims["exp"].(float64)
	if !ok || time.Unix(int64(exp), 0).Before(time.Now()) {
		t.Fatalf("claim exp = %v, want future timestamp", claims["exp"])
	}
	if _, ok := claims["email"]; ok {
		t.Fatalf("claim email must not be in token (PII)")
	}
}

func TestService_Login_InvalidCredentials(t *testing.T) {
	validPass := strings.Repeat("a", 12)

	tests := []struct {
		name            string
		email           string
		password        string
		repoUser        models.User
		repoErr         error
		verifyOK        bool
		wantRepoCalls   int
		wantVerifyCalls int
	}{
		{
			name:     "user not found",
			email:    "ghost@test.com",
			password: validPass,
			repoErr:  errs.ErrUserNotFound,
			// не найден и неверный пароль снаружи неразличимы,
			// в том числе по времени: dummy-Verify обязателен
			wantRepoCalls:   1,
			wantVerifyCalls: 1,
		},
		{
			name:            "wrong password",
			email:           "test@test.com",
			password:        validPass,
			repoUser:        models.User{ID: 8, PassHash: "stored-phc-hash"},
			verifyOK:        false,
			wantRepoCalls:   1,
			wantVerifyCalls: 1,
		},
		{
			name:            "invalid email short-circuits before repo",
			email:           "user@localhost",
			password:        validPass,
			wantRepoCalls:   0,
			wantVerifyCalls: 0,
		},
		{
			name:            "short password short-circuits before repo",
			email:           "test@test.com",
			password:        strings.Repeat("a", 11),
			wantRepoCalls:   0,
			wantVerifyCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &storageFake{getUserUser: tt.repoUser, getUserErr: tt.repoErr}
			hasher := &hasherFake{verifyOK: tt.verifyOK}
			service := newTestService(fake, hasher, time.Hour, "test-secret", 30*24*time.Hour)

			tokens, err := service.Login(context.Background(), tt.email, tt.password)

			if !errors.Is(err, errs.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			if tokens.AccessToken != "" || tokens.RefreshToken != "" {
				t.Fatalf("tokens must be empty, got %+v", tokens)
			}
			if fake.saveRefreshCalls != 0 {
				t.Fatalf("SaveRefreshToken calls = %d, want 0", fake.saveRefreshCalls)
			}
			if fake.getUserCalls != tt.wantRepoCalls {
				t.Fatalf("GetUser calls = %d, want %d", fake.getUserCalls, tt.wantRepoCalls)
			}
			if hasher.verifyCalls != tt.wantVerifyCalls {
				t.Fatalf("Verify calls = %d, want %d", hasher.verifyCalls, tt.wantVerifyCalls)
			}
			if hasher.hashCalls != 0 {
				t.Fatalf("Hash calls = %d, want 0", hasher.hashCalls)
			}
		})
	}
}

func TestService_Login_BrokenHashIsInternal(t *testing.T) {
	//Arrange: Verify вернул error — хеш в базе битый, это сбой, не неверный пароль
	fake := &storageFake{
		getUserUser: models.User{ID: 8, PassHash: "not-a-phc-hash"},
	}
	hasher := &hasherFake{verifyErr: errors.New("phc parse failed")}
	service := newTestService(fake, hasher, time.Hour, "test-secret", 30*24*time.Hour)

	//Act
	tokens, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if errors.Is(err, errs.ErrInvalidCredentials) {
		t.Fatalf("broken hash must not look like invalid credentials: %v", err)
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Fatalf("tokens must be empty, got %+v", tokens)
	}
}

func TestService_Login_LockedAccount(t *testing.T) {
	//Arrange: активная блокировка
	future := time.Now().Add(10 * time.Minute)
	fake := &storageFake{
		getUserUser:   models.User{ID: 8, PassHash: "stored-phc-hash"},
		checkLockTime: &future,
	}
	hasher := &hasherFake{verifyOK: true} // пароль ВЕРНЫЙ — всё равно отказ
	service := newTestService(fake, hasher, time.Hour, "s", time.Hour)

	//Act
	tokens, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if !errors.Is(err, errs.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Fatalf("tokens must be empty, got %+v", tokens)
	}
	if hasher.verifyCalls != 0 {
		t.Fatalf("Verify calls = %d, want 0: заблокированный аккаунт не тратит Argon2", hasher.verifyCalls)
	}
	if fake.resetCalls != 0 {
		t.Fatalf("Reset calls = %d, want 0", fake.resetCalls)
	}
}

func TestService_Login_ExpiredLockAllowsLogin(t *testing.T) {
	//Arrange: блокировка в прошлом — юзер снова допущен
	past := time.Now().Add(-time.Minute)
	fake := &storageFake{
		getUserUser:   models.User{ID: 8, PassHash: "stored-phc-hash"},
		checkLockTime: &past,
	}
	hasher := &hasherFake{verifyOK: true}
	service := newTestService(fake, hasher, time.Hour, "s", time.Hour)

	//Act
	tokens, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("expected token pair, got %+v", tokens)
	}
	if fake.resetCalls != 1 {
		t.Fatalf("Reset calls = %d, want 1: успех сбрасывает счётчик", fake.resetCalls)
	}
}

func TestService_Login_FailureThatLocksReturnsTooManyAttempts(t *testing.T) {
	//Arrange: неверный пароль, и инкремент сообщил «теперь заблокирован»
	future := time.Now().Add(15 * time.Minute)
	fake := &storageFake{
		getUserUser:       models.User{ID: 8, PassHash: "stored-phc-hash"},
		incrementLockTime: &future,
	}
	hasher := &hasherFake{verifyOK: false}
	service := newTestService(fake, hasher, time.Hour, "s", time.Hour)

	//Act
	_, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if !errors.Is(err, errs.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
	if fake.incrementCalls != 1 {
		t.Fatalf("Increment calls = %d, want 1", fake.incrementCalls)
	}
}

func TestService_Login_FailureBeforeLockIsInvalidCredentials(t *testing.T) {
	//Arrange: неверный пароль, лимит ещё не исчерпан (инкремент вернул nil)
	fake := &storageFake{
		getUserUser: models.User{ID: 8, PassHash: "stored-phc-hash"},
	}
	hasher := &hasherFake{verifyOK: false}
	service := newTestService(fake, hasher, time.Hour, "s", time.Hour)

	//Act
	_, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if !errors.Is(err, errs.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if fake.incrementCalls != 1 {
		t.Fatalf("Increment calls = %d, want 1", fake.incrementCalls)
	}
}

func TestService_Login_ResetFailureStillLogsIn(t *testing.T) {
	//Arrange: пароль верный, сброс счётчика упал — юзер не должен страдать
	fake := &storageFake{
		getUserUser: models.User{ID: 8, PassHash: "stored-phc-hash"},
		resetErr:    errors.New("db connection lost"),
	}
	hasher := &hasherFake{verifyOK: true}
	service := newTestService(fake, hasher, time.Hour, "s", time.Hour)

	//Act
	tokens, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("expected token pair, got %+v", tokens)
	}
}
