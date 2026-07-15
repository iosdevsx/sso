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
		Log:             slog.New(slog.DiscardHandler),
		UserStorage:     storage,
		TokenStorage:    storage,
		PassHasher:      hasher,
		TokenTTL:        tokenTTL,
		TokenSecret:     secret,
		RefreshTokenTTL: refreshTTL,
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
