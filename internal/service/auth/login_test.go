package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/domain/models"
)

// fake хранилища для Login: настраиваемый GetUser, SaveUser не используется.
type userProviderFake struct {
	returnUser models.User
	returnErr  error
	calls      int
	gotEmail   string
}

func (f *userProviderFake) GetUser(ctx context.Context, email string) (models.User, error) {
	f.calls++
	f.gotEmail = email
	return f.returnUser, f.returnErr
}

func (f *userProviderFake) SaveUser(ctx context.Context, email string, passHash string) (int64, error) {
	return 0, nil
}

// fake hasher для Login: явно управляемый результат Verify.
type verifierFake struct {
	returnOK    bool
	returnErr   error
	gotPassword string
	gotHash     string
}

func (f *verifierFake) Hash(password string) (string, error) {
	return "", nil
}

func (f *verifierFake) Verify(password string, hash string) (bool, error) {
	f.gotPassword = password
	f.gotHash = hash
	return f.returnOK, f.returnErr
}

func TestService_Login_Success(t *testing.T) {
	//Arrange
	const secret = "test-secret"
	const ttl = time.Hour
	repo := &userProviderFake{
		returnUser: models.User{ID: 8, Email: "test@test.com", PassHash: "stored-phc-hash"},
	}
	verifier := &verifierFake{returnOK: true}
	service := NewService(slog.New(slog.DiscardHandler), repo, verifier, ttl, secret)

	//Act
	token, err := service.Login(context.Background(), "  Test@Test.COM  ", "correct-password-123")

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if repo.gotEmail != "test@test.com" {
		t.Fatalf("GetUser got %q, want canonical %q", repo.gotEmail, "test@test.com")
	}
	if verifier.gotHash != "stored-phc-hash" {
		t.Fatalf("Verify got hash %q, want stored hash", verifier.gotHash)
	}

	parsed, err := jwtlib.Parse(
		token,
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
		name          string
		email         string
		password      string
		repoUser      models.User
		repoErr       error
		verifyOK      bool
		wantRepoCalls int
	}{
		{
			name:     "user not found",
			email:    "ghost@test.com",
			password: validPass,
			repoErr:  errs.ErrUserNotFound,
			// не найден и неверный пароль снаружи неразличимы
			wantRepoCalls: 1,
		},
		{
			name:          "wrong password",
			email:         "test@test.com",
			password:      validPass,
			repoUser:      models.User{ID: 8, PassHash: "stored-phc-hash"},
			verifyOK:      false,
			wantRepoCalls: 1,
		},
		{
			name:          "invalid email short-circuits before repo",
			email:         "user@localhost",
			password:      validPass,
			wantRepoCalls: 0,
		},
		{
			name:          "short password short-circuits before repo",
			email:         "test@test.com",
			password:      strings.Repeat("a", 11),
			wantRepoCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &userProviderFake{returnUser: tt.repoUser, returnErr: tt.repoErr}
			verifier := &verifierFake{returnOK: tt.verifyOK}
			service := NewService(slog.New(slog.DiscardHandler), repo, verifier, time.Hour, "test-secret")

			token, err := service.Login(context.Background(), tt.email, tt.password)

			if !errors.Is(err, errs.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			if token != "" {
				t.Fatalf("token = %q, want empty", token)
			}
			if repo.calls != tt.wantRepoCalls {
				t.Fatalf("GetUser calls = %d, want %d", repo.calls, tt.wantRepoCalls)
			}
		})
	}
}

func TestService_Login_BrokenHashIsInternal(t *testing.T) {
	//Arrange: Verify вернул error — хеш в базе битый, это сбой, не неверный пароль
	repo := &userProviderFake{
		returnUser: models.User{ID: 8, PassHash: "not-a-phc-hash"},
	}
	verifier := &verifierFake{returnErr: errors.New("phc parse failed")}
	service := NewService(slog.New(slog.DiscardHandler), repo, verifier, time.Hour, "test-secret")

	//Act
	token, err := service.Login(context.Background(), "test@test.com", strings.Repeat("a", 12))

	//Assert
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if errors.Is(err, errs.ErrInvalidCredentials) {
		t.Fatalf("broken hash must not look like invalid credentials: %v", err)
	}
	if token != "" {
		t.Fatalf("token = %q, want empty", token)
	}
}
