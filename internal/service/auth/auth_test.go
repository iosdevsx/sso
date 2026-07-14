package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/iosdevsx/sso/internal/domain/errs"
)

type userSaverFake struct {
	returnID    int64
	calls       int
	gotEmail    string
	gotPassHash string
	returnErr   error
}

func (f *userSaverFake) SaveUser(ctx context.Context, email string, passHash string) (userID int64, err error) {
	f.calls++
	f.gotEmail = email
	f.gotPassHash = passHash
	return f.returnID, f.returnErr
}

type userHasherFake struct {
	calls       int
	gotPassHash string
	returnHash  string
	returnErr   error
}

func (f *userHasherFake) Hash(password string) (string, error) {
	f.calls++
	return f.returnHash, f.returnErr
}

func (f *userHasherFake) Verify(password string, hash string) (bool, error) {
	f.calls++
	f.gotPassHash = hash
	return f.gotPassHash == f.returnHash, f.returnErr
}

func TestService_Register_Success(t *testing.T) {
	//Arrange
	fake := &userSaverFake{
		returnID: 42,
	}
	hasher := &userHasherFake{
		returnHash: "fake-phc-hash",
	}
	service := NewService(
		slog.New(slog.DiscardHandler), fake, hasher, nil, 0,
	)
	email := "test@test.com"
	password := "test_password"

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	if gotUserID != fake.returnID {
		t.Fatalf("userId incorrect, want %d, got %d", fake.returnID, gotUserID)
	}

	if email != fake.gotEmail {
		t.Fatalf("incorrect email, want %s, got %s", email, fake.gotEmail)
	}

	if fake.gotPassHash != hasher.returnHash {
		t.Fatalf("pass hash does not match")
	}

	if fake.calls != 1 {
		t.Fatalf("SaveUser calls = %d, want 1", fake.calls)
	}
}

func TestService_RegisterInvalidEmail(t *testing.T) {
	pass := strings.Repeat("a", 12)

	tests := []struct {
		name     string
		email    string
		password string
		want     error
	}{
		{name: "invalid email", email: "user <test@test.com>", password: pass, want: errs.ErrInvalidEmail},
		{name: "invalid domain", email: "test@localhost", password: pass, want: errs.ErrInvalidEmail},
		{name: "invalid ascii", email: "TEST@пример.рф", password: pass, want: errs.ErrInvalidEmail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &userSaverFake{
				returnID: 42,
			}
			hasher := &userHasherFake{
				returnHash: "fake-phc-hash",
			}
			service := NewService(
				slog.New(slog.DiscardHandler), fake, hasher, nil, 0,
			)
			gotUserID, err := service.Register(context.Background(), tt.email, tt.password)
			if err == nil {
				t.Fatalf("expected err %v, got %v", errs.ErrInvalidEmail, err)
			}
			if gotUserID != 0 {
				t.Fatalf("expected empty user, got %v", err)
			}
			if fake.calls != 0 {
				t.Fatalf("SaveUser calls = %d, want 0", fake.calls)
			}
		})
	}
}

func TestService_Register_UserAlreadyExists(t *testing.T) {
	//Arrange
	fake := &userSaverFake{
		returnErr: errs.ErrUserExists,
	}
	hasher := &userHasherFake{
		returnHash: "fake-phc-hash",
	}
	service := NewService(
		slog.New(slog.DiscardHandler), fake, hasher, nil, 0,
	)
	email := "test@test.com"
	password := "test_password"

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)

	//Assert
	if !errors.Is(err, errs.ErrUserExists) {
		t.Fatalf("Incorrect error, want %v, got %v", errs.ErrUserExists, err)
	}

	if fake.calls != 1 {
		t.Fatalf("SaveUser calls = %d, want 1", fake.calls)
	}

	if gotUserID != 0 {
		t.Fatalf("got invalid userID, want 0, got %d", gotUserID)
	}
}

func TestService_Register_PasswordTooLong(t *testing.T) {
	//Arrange
	fake := &userSaverFake{}
	hasher := &userHasherFake{
		returnHash: "fake-phc-hash",
	}
	service := NewService(
		slog.New(slog.DiscardHandler), fake, hasher, nil, 0,
	)
	email := "test@test.com"
	password := strings.Repeat("a", 129)

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)
	if !errors.Is(err, errs.ErrPasswordTooLong) {
		t.Fatalf("Incorrect error, want %v, got %v", errs.ErrPasswordTooLong, err)
	}

	if fake.calls != 0 {
		t.Fatalf("SaveUser calls = %d, want 0", fake.calls)
	}

	if gotUserID != 0 {
		t.Fatalf("got invalid userID, want 0, got %d", gotUserID)
	}
}

func TestService_Register_PasswordTooShort(t *testing.T) {
	//Arrange
	fake := &userSaverFake{}
	hasher := &userHasherFake{
		returnHash: "fake-phc-hash",
	}
	service := NewService(
		slog.New(slog.DiscardHandler), fake, hasher, nil, 0,
	)
	email := "test@test.com"
	password := strings.Repeat("a", 11)

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)
	if !errors.Is(err, errs.ErrPasswordTooShort) {
		t.Fatalf("Incorrect error, want %v, got %v", errs.ErrPasswordTooShort, err)
	}

	if fake.calls != 0 {
		t.Fatalf("SaveUser calls = %d, want 0", fake.calls)
	}

	if gotUserID != 0 {
		t.Fatalf("got invalid userID, want 0, got %d", gotUserID)
	}
}
