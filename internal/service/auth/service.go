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

type TokenStorage interface {
	SaveRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
	ConsumeRefreshToken(ctx context.Context, tokenHash string) (int64, error)
}

type PassHasher interface {
	Hash(password string) (string, error)
	Verify(password string, hash string) (bool, error)
}

type ServiceParams struct {
	Log             *slog.Logger
	UserStorage     UserStorage
	TokenStorage    TokenStorage
	PassHasher      PassHasher
	TokenTTL        time.Duration
	TokenSecret     string
	RefreshTokenTTL time.Duration
}

type Service struct {
	log             *slog.Logger
	userStorage     UserStorage
	tokenStorage    TokenStorage
	passHasher      PassHasher
	tokenTTL        time.Duration
	tokenSecret     string
	refreshTokenTTL time.Duration
}

func NewService(
	params ServiceParams,
) *Service {
	return &Service{
		log:             params.Log,
		userStorage:     params.UserStorage,
		tokenStorage:    params.TokenStorage,
		passHasher:      params.PassHasher,
		tokenTTL:        params.TokenTTL,
		tokenSecret:     params.TokenSecret,
		refreshTokenTTL: params.RefreshTokenTTL,
	}
}
