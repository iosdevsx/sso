package auth

import (
	"context"
	"errors"

	"github.com/iosdevsx/sso/internal/domain/errs"
)

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	const operation = "service.auth.logout"
	hash := hashRefresh(refreshToken)
	_, err := s.tokenStorage.ConsumeRefreshToken(ctx, hash)
	if err != nil && !errors.Is(err, errs.ErrRefreshTokenNotFound) {
		return errs.Wrap(operation, err)
	}
	return nil
}
