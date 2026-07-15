package auth

import (
	"context"
	"errors"
	"time"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/domain/models"
	"github.com/iosdevsx/sso/internal/lib/jwt"
)

func (s *Service) Refresh(ctx context.Context, refreshToken string) (models.Tokens, error) {
	const operation = "service.auth.refresh"

	userID, err := s.tokenStorage.ConsumeRefreshToken(
		ctx,
		hashRefresh(refreshToken),
	)

	if errors.Is(err, errs.ErrRefreshTokenNotFound) {
		return models.Tokens{}, errs.Wrap(operation, errs.ErrInvalidRefreshToken)
	}

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	rawRefresh, hashRefreshToken, err := newRefreshToken()

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	exp := time.Now().Add(s.refreshTokenTTL)
	err = s.tokenStorage.SaveRefreshToken(ctx, userID, hashRefreshToken, exp)

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	accessToken, err := jwt.NewToken(userID, s.tokenTTL, s.tokenSecret)

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	return models.Tokens{AccessToken: accessToken, RefreshToken: rawRefresh}, nil
}
