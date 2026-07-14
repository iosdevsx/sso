package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/iosdevsx/sso/internal/domain/models"
)

type UserStorage interface {
	SaveUser(ctx context.Context, email string, passHash string) (userID int64, err error)
	GetUser(ctx context.Context, email string) (models.User, error)
}

type PassHasher interface {
	Hash(password string) (string, error)
	Verify(password string, hash string) (bool, error)
}

type Service struct {
	log         *slog.Logger
	userStorage UserStorage
	passHasher  PassHasher
	tokenTTL    time.Duration
	tokenSecret string
}

func NewService(
	log *slog.Logger,
	userStorage UserStorage,
	passHasher PassHasher,
	tokenTTL time.Duration,
	tokenSecret string,
) *Service {
	return &Service{
		log:         log,
		userStorage: userStorage,
		passHasher:  passHasher,
		tokenTTL:    tokenTTL,
		tokenSecret: tokenSecret,
	}
}
