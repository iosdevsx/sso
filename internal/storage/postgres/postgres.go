package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/domain/models"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func NewStorage(pool *pgxpool.Pool) *Storage {
	return &Storage{pool: pool}
}

const (
	consumeRefreshToken = `
		update refresh_tokens 
		set revoked_at=current_timestamp 
		where token_hash = $1 and revoked_at is null and expires_at > now()
		returning user_id
	`
	saveRefreshToken = `
		insert into refresh_tokens(
			user_id, token_hash, expires_at
		) values(
			$1, $2, $3
		)	
	`
)

func (s *Storage) SaveUser(ctx context.Context, email string, passHash string) (int64, error) {
	const operation = "storage.postgres.saveUser"
	const query = `
		insert into users(
			email, 
			pass_hash
		) 
		values(
			$1,
			$2
		)
		returning (
			id
		);
	`
	var userID int64
	poolErr := s.pool.QueryRow(ctx, query, email, passHash).Scan(
		&userID,
	)
	if poolErr != nil {
		var err *pgconn.PgError
		if errors.As(poolErr, &err) && err.Code == pgerrcode.UniqueViolation {
			return 0, errs.ErrUserExists
		}
		return 0, errs.Wrap(operation, poolErr)
	}

	return userID, nil
}

func (s *Storage) GetUser(ctx context.Context, email string) (models.User, error) {
	const operation = "storage.postgres.getUser"
	const query = `
		select id, email, pass_hash from users where email = $1
	`
	var user models.User
	err := s.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PassHash,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return models.User{}, errs.Wrap(operation, errs.ErrUserNotFound)
	}

	if err != nil {
		return models.User{}, errs.Wrap(operation, err)
	}

	return user, nil
}

func (s *Storage) SaveRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	const operation = "storage.postgres.saveRefreshToken"

	_, err := s.pool.Exec(ctx, saveRefreshToken, userID, tokenHash, expiresAt)

	if err != nil {
		return errs.Wrap(operation, err)
	}

	return nil
}

func (s *Storage) ConsumeRefreshToken(ctx context.Context, tokenHash string) (int64, error) {
	const operation = "storage.postgres.consumeRefreshToken"

	var userID int64
	err := s.pool.QueryRow(ctx, consumeRefreshToken, tokenHash).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errs.Wrap(operation, errs.ErrRefreshTokenNotFound)
	}

	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	return userID, nil
}

func (s *Storage) IncrementFailedLoginAttempt(ctx context.Context, userID int64, maxAttempts int, lockUntil time.Time) (*time.Time, error) {
	const operation = "storage.postgres.incrementFailedLoginAttempt"
	const query = `
		insert into login_attempts (user_id) 
		values($1) 
		on conflict (user_id) 
		do update set 
		count=least(login_attempts.count + 1, $2),
		locked_until=case when least(login_attempts.count + 1, $2) >= $2
		then $3
		else login_attempts.locked_until end
		returning locked_until
	`
	var lockedUntil *time.Time
	err := s.pool.QueryRow(ctx, query, userID, maxAttempts, lockUntil).Scan(&lockedUntil)

	if err != nil {
		return nil, errs.Wrap(operation, err)
	}

	return lockedUntil, nil
}

func (s *Storage) CheckAccountLock(ctx context.Context, userID int64) (*time.Time, error) {
	const operation = "storage.postgres.checkAccountLock"
	const query = `
		select locked_until from login_attempts where user_id = $1
	`
	var locked *time.Time
	err := s.pool.QueryRow(ctx, query, userID).Scan(&locked)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, errs.Wrap(operation, err)
	}

	return locked, nil
}

func (s *Storage) ResetAccountAttempts(ctx context.Context, userID int64) error {
	const operation = "storage.postgres.resetAccountAttempts"
	const query = `
		delete from login_attempts where user_id = $1
	`
	_, err := s.pool.Exec(ctx, query, userID)

	if err != nil {
		return errs.Wrap(operation, err)
	}

	return nil
}

func (s *Storage) DeleteExpiredRefreshTokens(ctx context.Context, retention time.Duration) (int64, error) {
	const operation = "storage.postgres.deleteExpiredRefreshTokens"
	const query = `
		delete from refresh_tokens where expires_at < $1
	`
	cutoff := time.Now().Add(-retention)

	commandTag, err := s.pool.Exec(ctx, query, cutoff)

	if err != nil {
		return 0, errs.Wrap(operation, err)
	}
	return commandTag.RowsAffected(), nil
}

func (s *Storage) RotateRefreshToken(
	ctx context.Context,
	oldRefreshTokenHash string,
	newRefreshTokenHash string,
	expiresAt time.Time,
) (int64, error) {
	const operation = "storage.postgres.rotateRefreshToken"
	tx, err := s.pool.Begin(ctx)

	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	defer tx.Rollback(ctx)

	var userID int64
	consumeErr := tx.QueryRow(ctx, consumeRefreshToken, oldRefreshTokenHash).Scan(&userID)

	if errors.Is(consumeErr, pgx.ErrNoRows) {
		return 0, errs.Wrap(operation, errs.ErrRefreshTokenNotFound)
	}

	if consumeErr != nil {
		return 0, errs.Wrap(operation, consumeErr)
	}

	_, saveErr := tx.Exec(ctx, saveRefreshToken, userID, newRefreshTokenHash, expiresAt)

	if saveErr != nil {
		return 0, errs.Wrap(operation, saveErr)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, errs.Wrap(operation, err)
	}

	return userID, nil
}
