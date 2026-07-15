package auth

import (
	"context"

	"github.com/iosdevsx/sso/internal/domain/errs"
)

func (service *Service) Register(ctx context.Context, email, password string) (int64, error) {
	const operation = "service.auth.register"

	canonicalEmail, err := canonicalizeEmail(email)
	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	normalizedPass, err := normalizePassword(password)
	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	// захешировать пароль
	passHash, err := service.passHasher.Hash(normalizedPass)
	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	// сохранить пользователя
	userID, err := service.userStorage.SaveUser(ctx, canonicalEmail, passHash)
	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	// вернуть id
	return userID, nil
}
