package auth

import (
	"context"
	"errors"
	"time"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/domain/models"
	"github.com/iosdevsx/sso/internal/lib/jwt"
	"github.com/iosdevsx/sso/internal/lib/sl"
)

const (
	timingAttackHash = "$argon2id$v=19$m=19456,t=2,p=1$h1VS32QZKcCcUSmecuW0kw$NEfuIr2Q/iijA+W0CVWhIBNr/Z4/qH5okr69vNZ22Uk"
)

func (s *Service) Login(ctx context.Context, email, password string) (models.Tokens, error) {
	const operation = "service.auth.login"

	//canonical email
	canonicalEmail, err := canonicalizeEmail(email)
	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, errs.ErrInvalidCredentials)
	}

	//canonical pass
	normalizedPass, err := normalizePassword(password)
	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, errs.ErrInvalidCredentials)
	}

	//get user
	model, err := s.userStorage.GetUser(ctx, canonicalEmail)
	if errors.Is(err, errs.ErrUserNotFound) {
		//fake verify with err handling for prevent timing attack
		s.passHasher.Verify(normalizedPass, timingAttackHash)
		return models.Tokens{}, errs.Wrap(operation, errs.ErrInvalidCredentials)
	}

	if err != nil {
		//fake verify with err handling for prevent timing attack
		s.passHasher.Verify(normalizedPass, timingAttackHash)
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	//Check account lock
	if err := s.checkAccountLock(ctx, model.ID); err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	//check creds
	ok, err := s.passHasher.Verify(normalizedPass, model.PassHash)
	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	if !ok {
		err := s.increaseFailedAttempt(ctx, model.ID)
		if err != nil {
			return models.Tokens{}, errs.Wrap(operation, err)
		}
		return models.Tokens{}, errs.Wrap(operation, errs.ErrInvalidCredentials)
	}

	//generate token
	token, err := jwt.NewToken(model.ID, s.authParams.TokenTTL, s.authParams.TokenSecret)

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	rawRefresh, hashRefresh, err := newRefreshToken()

	if err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	if err := s.tokenStorage.SaveRefreshToken(ctx, model.ID, hashRefresh, time.Now().Add(s.authParams.RefreshTokenTTL)); err != nil {
		return models.Tokens{}, errs.Wrap(operation, err)
	}

	if err := s.loginAttemptsStorage.ResetAccountAttempts(ctx, model.ID); err != nil {
		s.log.Error("internal server error", sl.Err(err))
		//Все равно пускаем пользователя дальше, даже если не удалось почистить кол-во неуспешных попыток
	}

	return models.Tokens{AccessToken: token, RefreshToken: rawRefresh}, nil
}

func (s *Service) checkAccountLock(ctx context.Context, userID int64) error {
	lockTime, err := s.loginAttemptsStorage.CheckAccountLock(ctx, userID)
	if err != nil {
		return err
	}

	if lockTime != nil && lockTime.After(time.Now()) {
		return errs.ErrTooManyAttempts
	}

	return nil
}

func (s *Service) increaseFailedAttempt(ctx context.Context, userID int64) error {
	t := time.Now().Add(s.authParams.LockDuration)
	lockTime, err := s.loginAttemptsStorage.IncrementFailedLoginAttempt(ctx, userID, s.authParams.MaxAttempts, t)
	if err != nil {
		return err
	}
	if lockTime != nil && lockTime.After(time.Now()) {
		return errs.ErrTooManyAttempts
	}
	return nil
}
