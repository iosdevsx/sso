package postgres

import (
	"context"
	"errors"
	"fmt"

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
		return 0, fmt.Errorf("%s: %w", operation, poolErr)
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
		return models.User{}, fmt.Errorf("%s: %w", operation, errs.ErrUserNotFound)
	}

	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", operation, err)
	}

	return user, nil
}
