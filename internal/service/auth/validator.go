package auth

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"golang.org/x/text/unicode/norm"
)

func canonicalizeEmail(email string) (string, error) {
	trimmedEmail := strings.ToLower(strings.TrimSpace(email))
	if len(trimmedEmail) > 254 {
		return "", errs.ErrInvalidEmail
	}
	parsedAddr, err := mail.ParseAddress(trimmedEmail)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errs.ErrInvalidEmail, err)
	}

	if parsedAddr.Name != "" {
		return "", errs.ErrInvalidEmail
	}
	addr := parsedAddr.Address

	for i := range len(addr) {
		if addr[i] > unicode.MaxASCII {
			return "", errs.ErrInvalidEmail
		}
	}

	at := strings.LastIndex(addr, "@")

	domain := addr[at+1:]

	if !strings.Contains(domain, ".") {
		return "", errs.ErrInvalidEmail
	}

	return addr, nil
}

func normalizePassword(password string) (string, error) {
	password = norm.NFC.String(password)
	count := utf8.RuneCountInString(password)
	if count < 12 {
		return "", errs.ErrPasswordTooShort
	}
	if count > 128 {
		return "", errs.ErrPasswordTooLong
	}
	return password, nil
}
