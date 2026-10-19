package security

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
)

// pbkdf2SHA256 is the password-based key derivation used for console
// credentials. Kept in its own file so the algorithm is swappable without
// touching the encoding and verification logic around it.
//
// PBKDF2-HMAC-SHA256 is the choice here because it needs no cgo and no external
// dependency (the Go standard library provides it as of 1.24), which keeps the
// server a single static binary — the reason the release pipeline can ship one
// file per platform.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}
	return key, nil
}
