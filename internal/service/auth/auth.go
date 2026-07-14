package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/iosdevsx/sso/internal/domain/models"
)

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash string) (userID int64, err error)
}

type PassHasher interface {
	Hash(password string) (string, error)
	Verify(password string, hash string) (bool, error)
}

type Service struct {
	log         *slog.Logger
	userSaver   UserSaver
	passHasher  PassHasher
	appProvider AppProvider
	tokenTTL    time.Duration
}

func NewService(
	log *slog.Logger,
	userSaver UserSaver,
	passHasher PassHasher,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Service {
	return &Service{
		log:         log,
		userSaver:   userSaver,
		passHasher:  passHasher,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

func (service *Service) Register(ctx context.Context, email, password string) (int64, error) {
	const operation = "service.auth.register"

	canonicalEmail, err := canonicalizeEmail(email)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", operation, err)
	}

	normalizedPass, err := normalizePassword(password)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", operation, err)
	}

	// захешировать пароль
	passHash, err := service.passHasher.Hash(normalizedPass)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", operation, err)
	}

	// сохранить пользователя
	userID, err := service.userSaver.SaveUser(ctx, canonicalEmail, passHash)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", operation, err)
	}

	// вернуть id
	return userID, nil
}
