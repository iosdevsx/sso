package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func NewToken(userID int64, tokenTTL time.Duration, secret string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": userID,
			"exp": time.Now().Add(tokenTTL).Unix(),
			"iat": time.Now().Unix(),
		})
	token, err := t.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}
