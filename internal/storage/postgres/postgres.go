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
	const query = `
		insert into refresh_tokens(
			user_id, token_hash, expires_at
		) values(
			$1, $2, $3
		)	
	`
	_, err := s.pool.Exec(ctx, query, userID, tokenHash, expiresAt)

	if err != nil {
		return errs.Wrap(operation, err)
	}

	return nil
}

func (s *Storage) ConsumeRefreshToken(ctx context.Context, tokenHash string) (int64, error) {
	const operation = "storage.postgres.consumeRefreshToken"
	const query = `
		update refresh_tokens 
		set revoked_at=current_timestamp 
		where token_hash = $1 and revoked_at is null and expires_at > now()
		returning user_id
	`

	var userID int64
	err := s.pool.QueryRow(ctx, query, tokenHash).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errs.Wrap(operation, errs.ErrRefreshTokenNotFound)
	}

	if err != nil {
		return 0, errs.Wrap(operation, err)
	}

	return userID, nil
}
