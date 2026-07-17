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
	rawRefresh, newRefreshHash, err := newRefreshToken()
	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}
	exp := time.Now().Add(s.authParams.RefreshTokenTTL)

	userID, err := s.tokenStorage.RotateRefreshToken(ctx, hashRefresh(refreshToken), newRefreshHash, exp)

	if errors.Is(err, errs.ErrRefreshTokenNotFound) {
		return models.Tokens{}, errs.Wrap(operation, errs.ErrInvalidRefreshToken)
	}

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	//Generate new access_token
	accessToken, err := jwt.NewToken(userID, s.authParams.TokenTTL, s.authParams.TokenSecret)

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	return models.Tokens{AccessToken: accessToken, RefreshToken: rawRefresh}, nil
}
