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

type LoginAttemptsStorage interface {
	ResetAccountAttempts(ctx context.Context, userID int64) error
	CheckAccountLock(ctx context.Context, userID int64) (*time.Time, error)
	IncrementFailedLoginAttempt(ctx context.Context, userID int64, maxAttempts int, lockUntil time.Time) (*time.Time, error)
}

type PassHasher interface {
	Hash(password string) (string, error)
	Verify(password string, hash string) (bool, error)
}

type ServiceParams struct {
	Log                  *slog.Logger
	UserStorage          UserStorage
	TokenStorage         TokenStorage
	LoginAttemptsStorage LoginAttemptsStorage
	PassHasher           PassHasher
	AuthParams           AuthParams
}

type AuthParams struct {
	TokenTTL        time.Duration
	TokenSecret     string
	RefreshTokenTTL time.Duration
	MaxAttempts     int
	LockDuration    time.Duration
}

type Service struct {
	log                  *slog.Logger
	userStorage          UserStorage
	tokenStorage         TokenStorage
	loginAttemptsStorage LoginAttemptsStorage
	passHasher           PassHasher
	authParams           AuthParams
}

func NewService(
	params ServiceParams,
) *Service {
	return &Service{
		log:                  params.Log,
		userStorage:          params.UserStorage,
		tokenStorage:         params.TokenStorage,
		loginAttemptsStorage: params.LoginAttemptsStorage,
		passHasher:           params.PassHasher,
		authParams:           params.AuthParams,
	}
}
