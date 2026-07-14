package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/lib/jwt"
)

const (
	timingAttackHash = "$argon2id$v=19$m=19456,t=2,p=1$h1VS32QZKcCcUSmecuW0kw$NEfuIr2Q/iijA+W0CVWhIBNr/Z4/qH5okr69vNZ22Uk"
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
		//fake verify with err handling for prevent timing attack
		s.passHasher.Verify(normalizedPass, timingAttackHash)
		return "", fmt.Errorf("%s: %w", operation, errs.ErrInvalidCredentials)
	}

	if err != nil {
		//fake verify with err handling for prevent timing attack
		s.passHasher.Verify(normalizedPass, timingAttackHash)
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
