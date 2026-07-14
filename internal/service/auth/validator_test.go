package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/iosdevsx/sso/internal/domain/errs"
)

func Test_ValidateEmail_Success(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "trim space", input: "   user@localhost.com  ", want: "user@localhost.com"},
		{name: "lowecase", input: "Alice@localhost.COM", want: "alice@localhost.com"},
		{name: "valid email", input: "ALICE@a.b  ", want: "alice@a.b"},
		{name: "valid email with specific chars", input: "alice+work@test.com", want: "alice+work@test.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalizeEmail(tt.input)
			if err != nil {
				t.Fatalf("test failed, got %s, want %s", got, tt.want)
			}
			if got != tt.want {
				t.Fatalf("test failed, got %s, want %s", got, tt.want)
			}
		})
	}
}

func Test_ValidateEmail_Invalid(t *testing.T) {
	longEmail := "a@a." + strings.Repeat("a", 254)
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{name: "empty email", input: "", want: errs.ErrInvalidEmail},
		{name: "invalid format", input: "Alice   @localhost.COM", want: errs.ErrInvalidEmail},
		{name: "invalid format", input: "USER a@b.c", want: errs.ErrInvalidEmail},
		{name: "invalid format", input: "Alice <a@b.c>", want: errs.ErrInvalidEmail},
		{name: "no domain", input: "user@localhost", want: errs.ErrInvalidEmail},
		{name: "no domain", input: "user@localhost.", want: errs.ErrInvalidEmail},
		{name: "no domain", input: "user@.localhost", want: errs.ErrInvalidEmail},
		{name: "too long", input: longEmail, want: errs.ErrInvalidEmail},
		{name: "no ascii symbols", input: "user@пример.рф", want: errs.ErrInvalidEmail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, err := canonicalizeEmail(tt.input)
			if email != "" {
				t.Fatalf("test failed, got %s, want %s", email, tt.want)
			}
			if !errors.Is(err, errs.ErrInvalidEmail) {
				t.Fatalf("test failed, got %s, want %s", err, tt.want)
			}
		})
	}
}

func Test_ValidatePassword_Valid(t *testing.T) {
	nfcLongCorrectPass := strings.Repeat("a", 127) + "e\u0301"
	minCorrectPass := strings.Repeat("a", 12)
	maxCorrectPass := strings.Repeat("a", 128)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "nfc norm correct password", input: nfcLongCorrectPass, want: strings.Repeat("a", 127) + "\u00e9"},
		{name: "min correct password", input: minCorrectPass, want: minCorrectPass},
		{name: "max correct password", input: maxCorrectPass, want: maxCorrectPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pass, err := normalizePassword(tt.input)
			if pass == "" {
				t.Fatalf("test failed, got %s, want %s", pass, tt.want)
			}
			if pass != tt.want {
				t.Fatalf("test failed, got %s, want %s", pass, tt.want)
			}
			if err != nil {
				t.Fatalf("test failed, got %s, want %s", err, tt.want)
			}
		})
	}
}

func Test_ValidatePassword_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{name: "short pass", input: "1", want: errs.ErrPasswordTooShort},
		{name: "long pass", input: strings.Repeat("a", 129), want: errs.ErrPasswordTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pass, err := normalizePassword(tt.input)
			if pass != "" {
				t.Fatalf("test failed, got %s, want %s", pass, tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("test failed, got %s, want %s", err, tt.want)
			}
		})
	}
}
