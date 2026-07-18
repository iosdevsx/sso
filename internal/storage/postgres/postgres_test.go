//go:build integration

package postgres

import (
	"context"
	"errors"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/storage/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var testStorage *Storage

func TestMain(m *testing.M) {
	dbName := "sso"
	dbUser := "test"
	dbPassword := "pass"

	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:17",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %s", err)
	}

	if err := migrations.Run(connStr); err != nil {
		log.Fatalf("failed to migrate: %s", err)
	}

	dbConfig, err := pgxpool.ParseConfig(connStr)

	if err != nil {
		log.Fatalf("failed to parse config: %s", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		log.Fatalf("failed to create pool: %s", err)
	}

	testStorage = NewStorage(pool)
	code := m.Run()

	pool.Close()
	if err := testcontainers.TerminateContainer(container); err != nil {
		log.Printf("failed to terminate container: %s", err) // не Fatalf: не затираем код тестов
	}

	os.Exit(code)
}

func cleanDB(t *testing.T) {
	const query = `truncate users, refresh_tokens, login_attempts restart identity cascade`
	t.Helper()
	_, err := testStorage.pool.Exec(t.Context(), query)
	if err != nil {
		t.Fatalf("failed to clean db: %v", err)
	}
}

func TestSaveUser_Duplicate(t *testing.T) {
	cleanDB(t)

	id, err := testStorage.SaveUser(t.Context(), "a@b.c", "hash")
	if err != nil {
		t.Fatalf("cannot save user %v", err)
	}
	if id <= 0 {
		t.Fatalf("id should be greater than zero: %v", err)
	}
	id, err = testStorage.SaveUser(t.Context(), "a@b.c", "hash")

	if !errors.Is(err, errs.ErrUserExists) {
		t.Fatalf("duplicated user error %v", err)
	}
}

func createTestUser(t *testing.T, email string) int64 {
	t.Helper()
	id, err := testStorage.SaveUser(t.Context(), email, "phc-hash-stub")
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return id
}

func tokenState(t *testing.T, hash string) (exists bool, revoked bool) {
	t.Helper()
	var revokedAt *time.Time
	err := testStorage.pool.QueryRow(t.Context(),
		`select revoked_at from refresh_tokens where token_hash = $1`, hash).Scan(&revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false
	}
	if err != nil {
		t.Fatalf("failed to query token state: %v", err)
	}
	return true, revokedAt != nil
}

func TestGetUser(t *testing.T) {
	cleanDB(t)
	id := createTestUser(t, "alice@test.com")

	user, err := testStorage.GetUser(t.Context(), "alice@test.com")
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if user.ID != id || user.Email != "alice@test.com" || user.PassHash != "phc-hash-stub" {
		t.Fatalf("unexpected user: %+v", user)
	}

	_, err = testStorage.GetUser(t.Context(), "ghost@test.com")
	if !errors.Is(err, errs.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
}

func TestRotateRefreshToken(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	exp := time.Now().Add(time.Hour)
	if err := testStorage.SaveRefreshToken(t.Context(), userID, "old-hash", exp); err != nil {
		t.Fatalf("save token: %v", err)
	}

	gotID, err := testStorage.RotateRefreshToken(t.Context(), "old-hash", "new-hash", exp)
	if err != nil {
		t.Fatalf("rotate: expected nil, got %v", err)
	}
	if gotID != userID {
		t.Fatalf("rotate returned user %d, want %d", gotID, userID)
	}

	if exists, revoked := tokenState(t, "old-hash"); !exists || !revoked {
		t.Fatalf("old token: exists=%v revoked=%v, want true/true", exists, revoked)
	}
	if exists, revoked := tokenState(t, "new-hash"); !exists || revoked {
		t.Fatalf("new token: exists=%v revoked=%v, want true/false", exists, revoked)
	}

	_, err = testStorage.RotateRefreshToken(t.Context(), "old-hash", "another-hash", exp)
	if !errors.Is(err, errs.ErrRefreshTokenNotFound) {
		t.Fatalf("reuse: want ErrRefreshTokenNotFound, got %v", err)
	}
	if exists, _ := tokenState(t, "another-hash"); exists {
		t.Fatal("token must not be inserted when consume fails (transaction!)")
	}
}

func TestRotateRefreshToken_Expired(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	past := time.Now().Add(-time.Minute)
	if err := testStorage.SaveRefreshToken(t.Context(), userID, "expired-hash", past); err != nil {
		t.Fatalf("save token: %v", err)
	}

	_, err := testStorage.RotateRefreshToken(t.Context(), "expired-hash", "new-hash", time.Now().Add(time.Hour))
	if !errors.Is(err, errs.ErrRefreshTokenNotFound) {
		t.Fatalf("expired: want ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestRotateRefreshToken_Concurrent(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	exp := time.Now().Add(time.Hour)
	if err := testStorage.SaveRefreshToken(t.Context(), userID, "contested-hash", exp); err != nil {
		t.Fatalf("save token: %v", err)
	}

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, newHash := range []string{"winner-hash-1", "winner-hash-2"} {
		wg.Add(1)
		go func(nh string) {
			defer wg.Done()
			_, err := testStorage.RotateRefreshToken(context.Background(), "contested-hash", nh, exp)
			results <- err
		}(newHash)
	}
	wg.Wait()
	close(results)

	var wins, rejections int
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, errs.ErrRefreshTokenNotFound):
			rejections++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 || rejections != 1 {
		t.Fatalf("wins=%d rejections=%d, want exactly 1/1", wins, rejections)
	}
}

func TestConsumeRefreshToken(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	exp := time.Now().Add(time.Hour)
	if err := testStorage.SaveRefreshToken(t.Context(), userID, "hash-1", exp); err != nil {
		t.Fatalf("save token: %v", err)
	}

	gotID, err := testStorage.ConsumeRefreshToken(t.Context(), "hash-1")
	if err != nil || gotID != userID {
		t.Fatalf("consume: got (%d, %v), want (%d, nil)", gotID, err, userID)
	}

	// повторный consume — токен уже погашен
	_, err = testStorage.ConsumeRefreshToken(t.Context(), "hash-1")
	if !errors.Is(err, errs.ErrRefreshTokenNotFound) {
		t.Fatalf("second consume: want ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestLoginAttempts_LockOnFifthFailure(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	const maxAttempts = 5
	lockUntil := time.Now().Add(15 * time.Minute)

	for i := 1; i <= 4; i++ {
		locked, err := testStorage.IncrementFailedLoginAttempt(t.Context(), userID, maxAttempts, lockUntil)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if locked != nil {
			t.Fatalf("attempt %d: unexpected lock %v", i, locked)
		}
	}

	locked, err := testStorage.IncrementFailedLoginAttempt(t.Context(), userID, maxAttempts, lockUntil)
	if err != nil {
		t.Fatalf("attempt 5: %v", err)
	}
	if locked == nil {
		t.Fatal("attempt 5 must lock the account")
	}

	locked, err = testStorage.IncrementFailedLoginAttempt(t.Context(), userID, maxAttempts, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("attempt 6: %v", err)
	}
	if locked == nil {
		t.Fatal("attempt 6 must re-lock")
	}

	check, err := testStorage.CheckAccountLock(t.Context(), userID)
	if err != nil || check == nil {
		t.Fatalf("check: got (%v, %v), want lock time", check, err)
	}

	if err := testStorage.ResetAccountAttempts(t.Context(), userID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	locked, err = testStorage.IncrementFailedLoginAttempt(t.Context(), userID, maxAttempts, lockUntil)
	if err != nil || locked != nil {
		t.Fatalf("after reset: got (%v, %v), want (nil, nil)", locked, err)
	}
}

func TestCheckAccountLock_NoRow(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	locked, err := testStorage.CheckAccountLock(t.Context(), userID)
	if err != nil || locked != nil {
		t.Fatalf("got (%v, %v), want (nil, nil): нет строки = не заблокирован", locked, err)
	}
}

func TestDeleteExpiredRefreshTokens(t *testing.T) {
	cleanDB(t)
	userID := createTestUser(t, "alice@test.com")

	save := func(hash string, exp time.Time) {
		t.Helper()
		if err := testStorage.SaveRefreshToken(t.Context(), userID, hash, exp); err != nil {
			t.Fatalf("save %s: %v", hash, err)
		}
	}
	save("ancient-hash", time.Now().Add(-60*24*time.Hour))
	save("recent-dead-hash", time.Now().Add(-10*24*time.Hour))
	save("alive-hash", time.Now().Add(time.Hour))

	deleted, err := testStorage.DeleteExpiredRefreshTokens(t.Context(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}

	if exists, _ := tokenState(t, "ancient-hash"); exists {
		t.Fatal("ancient token must be deleted")
	}
	for _, h := range []string{"recent-dead-hash", "alive-hash"} {
		if exists, _ := tokenState(t, h); !exists {
			t.Fatalf("token %s must survive cleanup", h)
		}
	}
}
