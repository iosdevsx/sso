package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/lib/jwt"
)

func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	const operation = "service.auth.login"
	//canonical email
	canonicalEmail, err := canonicalizeEmail(email)
	if err != nil {
		return "", fmt.Errorf("%s: %w", operation, errs.ErrInvalidCredentials)
	}

	//canonical pass
	normalizedPass, err := normalizePassword(password)
	if err != nil {
		return "", fmt.Errorf("%s: %w", operation, errs.ErrInvalidCredentials)
	}

	//get user
	model, err := s.userStorage.GetUser(ctx, canonicalEmail)
	if errors.Is(err, errs.ErrUserNotFound) {
		return "", fmt.Errorf("%s: %w", operation, errs.ErrInvalidCredentials)
	}

	if err != nil {
		return "", fmt.Errorf("%s: %w", operation, err)
	}

	//check creds
	ok, err := s.passHasher.Verify(normalizedPass, model.PassHash)
	if err != nil {
		return "", fmt.Errorf("%s: %w", operation, err)
	}

	if !ok {
		return "", fmt.Errorf("%s: %w", operation, errs.ErrInvalidCredentials)
	}

	//generate token
	token, err := jwt.NewToken(model.ID, s.tokenTTL, s.tokenSecret)

	if err != nil {
		return "", fmt.Errorf("%s: %w", operation, err)
	}

	return token, nil
}
