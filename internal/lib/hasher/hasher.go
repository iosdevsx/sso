package hasher

import (
	"github.com/alexedwards/argon2id"
)

type Hasher struct {
	params argon2id.Params
}

func New() *Hasher {
	return &Hasher{params: argon2id.Params{
		Memory: 19456, Iterations: 2, Parallelism: 1,
		SaltLength: 16, KeyLength: 32,
	}}
}

func (h *Hasher) Hash(password string) (string, error) {
	return argon2id.CreateHash(password, &h.params)
}

func (h *Hasher) Verify(password string, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
