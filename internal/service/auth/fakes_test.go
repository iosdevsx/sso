package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/iosdevsx/sso/internal/domain/models"
)

// newTestService собирает Service с fake-зависимостями.
// Единственное место, которое нужно править при смене конструктора.
func newTestService(storage *storageFake, hasher *hasherFake, tokenTTL time.Duration, secret string, refreshTTL time.Duration) *Service {
	return NewService(ServiceParams{
		Log:                  slog.New(slog.DiscardHandler),
		UserStorage:          storage,
		TokenStorage:         storage,
		LoginAttemptsStorage: storage,
		PassHasher:           hasher,
		AuthParams: AuthParams{
			TokenTTL:        tokenTTL,
			TokenSecret:     secret,
			RefreshTokenTTL: refreshTTL,
			MaxAttempts:     5,
			LockDuration:    time.Hour,
		},
	})
}

// storageFake реализует UserStorage и TokenStorage.
// Поля сгруппированы по методам: return-поля — что вернуть,
// got-поля — что метод получил, *Calls — сколько раз вызван.
type storageFake struct {
	// SaveUser
	saveUserID      int64
	saveUserErr     error
	saveUserCalls   int
	gotSaveEmail    string
	gotSavePassHash string

	// GetUser
	getUserUser  models.User
	getUserErr   error
	getUserCalls int
	gotGetEmail  string

	// SaveRefreshToken
	saveRefreshErr   error
	saveRefreshCalls int
	gotRefreshUserID int64
	gotRefreshHash   string
	gotRefreshExp    time.Time

	// ConsumeRefreshToken
	consumeUserID  int64
	consumeErr     error
	consumeCalls   int
	gotConsumeHash string

	// RotateRefreshToken
	rotateUserID     int64
	rotateErr        error
	rotateCalls      int
	gotRotateOldHash string
	gotRotateNewHash string
	gotRotateExp     time.Time

	// CheckAccountLock
	checkLockTime  *time.Time
	checkLockErr   error
	checkLockCalls int

	// IncrementFailedLoginAttempt
	incrementLockTime  *time.Time
	incrementErr       error
	incrementCalls     int
	gotIncrementUserID int64

	// ResetAccountAttempts
	resetErr   error
	resetCalls int
}

func (f *storageFake) CheckAccountLock(ctx context.Context, userID int64) (*time.Time, error) {
	f.checkLockCalls++
	return f.checkLockTime, f.checkLockErr
}

func (f *storageFake) IncrementFailedLoginAttempt(ctx context.Context, userID int64, maxAttempts int, lockUntil time.Time) (*time.Time, error) {
	f.incrementCalls++
	f.gotIncrementUserID = userID
	return f.incrementLockTime, f.incrementErr
}

func (f *storageFake) ResetAccountAttempts(ctx context.Context, userID int64) error {
	f.resetCalls++
	return f.resetErr
}

func (f *storageFake) SaveUser(ctx context.Context, email string, passHash string) (int64, error) {
	f.saveUserCalls++
	f.gotSaveEmail = email
	f.gotSavePassHash = passHash
	return f.saveUserID, f.saveUserErr
}

func (f *storageFake) GetUser(ctx context.Context, email string) (models.User, error) {
	f.getUserCalls++
	f.gotGetEmail = email
	return f.getUserUser, f.getUserErr
}

func (f *storageFake) SaveRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	f.saveRefreshCalls++
	f.gotRefreshUserID = userID
	f.gotRefreshHash = tokenHash
	f.gotRefreshExp = expiresAt
	return f.saveRefreshErr
}

func (f *storageFake) ConsumeRefreshToken(ctx context.Context, tokenHash string) (int64, error) {
	f.consumeCalls++
	f.gotConsumeHash = tokenHash
	return f.consumeUserID, f.consumeErr
}

func (f *storageFake) RotateRefreshToken(
	ctx context.Context,
	oldRefreshTokenHash string,
	newRefreshTokenHash string,
	expiresAt time.Time,
) (int64, error) {
	f.rotateCalls++
	f.gotRotateOldHash = oldRefreshTokenHash
	f.gotRotateNewHash = newRefreshTokenHash
	f.gotRotateExp = expiresAt
	return f.rotateUserID, f.rotateErr
}

// hasherFake реализует PassHasher с явно управляемыми результатами.
type hasherFake struct {
	// Hash
	returnHash      string
	hashErr         error
	hashCalls       int
	gotHashPassword string

	// Verify
	verifyOK          bool
	verifyErr         error
	verifyCalls       int
	gotVerifyPassword string
	gotVerifyHash     string
}

func (f *hasherFake) Hash(password string) (string, error) {
	f.hashCalls++
	f.gotHashPassword = password
	return f.returnHash, f.hashErr
}

func (f *hasherFake) Verify(password string, hash string) (bool, error) {
	f.verifyCalls++
	f.gotVerifyPassword = password
	f.gotVerifyHash = hash
	return f.verifyOK, f.verifyErr
}
