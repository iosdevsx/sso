package hasher

import (
	"testing"
)

func Test_RoundTrip_Valid(t *testing.T) {
	tests := []string{
		"pass3",
		"jksadghjkasdgjasdg",
		" asdfg asdg sadg",
		" 123123123123123",
	}

	hasher := New()
	for _, tt := range tests {
		t.Run("valid test", func(t *testing.T) {
			hash, err := hasher.Hash(tt)
			if err != nil {
				t.Fatalf("Expected valid hash, got %v", err)
			}
			ok, err := hasher.Verify(tt, hash)
			if err != nil || !ok {
				t.Fatalf("Expected valid verify, got %v", err)
			}
		})
	}
}

func Test_WrongPassword(t *testing.T) {
	hasher := New()
	hash, err := hasher.Hash("valid-pass")
	if err != nil {
		t.Fatalf("Expected valid hash, got %v", err)
	}
	ok, err := hasher.Verify("wrong-pass", hash)

	if ok {
		t.Fatalf("expected false, got true")
	}
}

func Test_WrongHash(t *testing.T) {
	hasher := New()
	_, err := hasher.Hash("valid-pass")
	if err != nil {
		t.Fatalf("Expected valid hash, got %v", err)
	}
	ok, err := hasher.Verify("valid-pass", "not-a-hash")

	if ok {
		t.Fatalf("expected false, got true")
	}
	if err == nil {
		t.Fatalf("expected err, got nil")
	}
}
