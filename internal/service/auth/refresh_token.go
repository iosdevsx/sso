package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func newRefreshToken() (raw string, hash string, err error) {
	key := make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		return "", "", err
	}

	raw = base64.RawURLEncoding.EncodeToString(key)
	hash = hashRefresh(raw)
	return raw, hash, nil
}

func hashRefresh(refreshToken string) string {
	sum := sha256.Sum256([]byte(refreshToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
