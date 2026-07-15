package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/iosdevsx/sso/internal/domain/errs"
)

func TestService_Register_Success(t *testing.T) {
	//Arrange
	fake := &storageFake{
		saveUserID: 42,
	}
	hasher := &hasherFake{
		returnHash: "fake-phc-hash",
	}
	service := newTestService(fake, hasher, 0, "", 0)
	email := "test@test.com"
	password := "test_password"

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)

	//Assert
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	if gotUserID != fake.saveUserID {
		t.Fatalf("userId incorrect, want %d, got %d", fake.saveUserID, gotUserID)
	}

	if email != fake.gotSaveEmail {
		t.Fatalf("incorrect email, want %s, got %s", email, fake.gotSaveEmail)
	}

	if fake.gotSavePassHash != hasher.returnHash {
		t.Fatalf("pass hash does not match")
	}

	if fake.saveUserCalls != 1 {
		t.Fatalf("SaveUser calls = %d, want 1", fake.saveUserCalls)
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
			fake := &storageFake{
				saveUserID: 42,
			}
			hasher := &hasherFake{
				returnHash: "fake-phc-hash",
			}
			service := newTestService(fake, hasher, 0, "", 0)
			gotUserID, err := service.Register(context.Background(), tt.email, tt.password)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected err %v, got %v", tt.want, err)
			}
			if gotUserID != 0 {
				t.Fatalf("expected empty user, got %v", err)
			}
			if fake.saveUserCalls != 0 {
				t.Fatalf("SaveUser calls = %d, want 0", fake.saveUserCalls)
			}
		})
	}
}

func TestService_Register_UserAlreadyExists(t *testing.T) {
	//Arrange
	fake := &storageFake{
		saveUserErr: errs.ErrUserExists,
	}
	hasher := &hasherFake{
		returnHash: "fake-phc-hash",
	}
	service := newTestService(fake, hasher, 0, "", 0)
	email := "test@test.com"
	password := "test_password"

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)

	//Assert
	if !errors.Is(err, errs.ErrUserExists) {
		t.Fatalf("Incorrect error, want %v, got %v", errs.ErrUserExists, err)
	}

	if fake.saveUserCalls != 1 {
		t.Fatalf("SaveUser calls = %d, want 1", fake.saveUserCalls)
	}

	if gotUserID != 0 {
		t.Fatalf("got invalid userID, want 0, got %d", gotUserID)
	}
}

func TestService_Register_PasswordTooLong(t *testing.T) {
	//Arrange
	fake := &storageFake{}
	hasher := &hasherFake{
		returnHash: "fake-phc-hash",
	}
	service := newTestService(fake, hasher, 0, "", 0)
	email := "test@test.com"
	password := strings.Repeat("a", 129)

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)
	if !errors.Is(err, errs.ErrPasswordTooLong) {
		t.Fatalf("Incorrect error, want %v, got %v", errs.ErrPasswordTooLong, err)
	}

	if fake.saveUserCalls != 0 {
		t.Fatalf("SaveUser calls = %d, want 0", fake.saveUserCalls)
	}

	if gotUserID != 0 {
		t.Fatalf("got invalid userID, want 0, got %d", gotUserID)
	}
}

func TestService_Register_PasswordTooShort(t *testing.T) {
	//Arrange
	fake := &storageFake{}
	hasher := &hasherFake{
		returnHash: "fake-phc-hash",
	}
	service := newTestService(fake, hasher, 0, "", 0)
	email := "test@test.com"
	password := strings.Repeat("a", 11)

	//Act
	gotUserID, err := service.Register(context.Background(), email, password)
	if !errors.Is(err, errs.ErrPasswordTooShort) {
		t.Fatalf("Incorrect error, want %v, got %v", errs.ErrPasswordTooShort, err)
	}

	if fake.saveUserCalls != 0 {
		t.Fatalf("SaveUser calls = %d, want 0", fake.saveUserCalls)
	}

	if gotUserID != 0 {
		t.Fatalf("got invalid userID, want 0, got %d", gotUserID)
	}
}
