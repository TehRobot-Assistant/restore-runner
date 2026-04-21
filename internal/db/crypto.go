package db

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Repo passwords (Restic/Borg/Kopia keyphrases) are stored encrypted in
// SQLite with AES-256-GCM. The master key is a 32-byte value generated
// on first run, stored in the settings table, and persists in /config
// alongside the database. Losing /config means losing both — same blast
// radius as losing the DB itself, so no separate key-escrow burden.

// EnsureMasterKey returns the existing master key, or generates one on
// first call. Idempotent.
func EnsureMasterKey(ctx context.Context, d *sql.DB) ([]byte, error) {
	existing, err := SettingGet(ctx, d, KeyMasterKey)
	if err != nil {
		return nil, err
	}
	if existing != "" {
		k, err := hex.DecodeString(existing)
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("master key in settings is corrupt (%d bytes)", len(k))
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := SettingSet(ctx, d, KeyMasterKey, hex.EncodeToString(k)); err != nil {
		return nil, err
	}
	return k, nil
}

// Encrypt seals plaintext with the master key. Output is hex-encoded
// nonce||ciphertext so it fits in a TEXT column. Empty plaintext returns
// empty output — callers use that for the "no password" (keyfile-only) case.
func Encrypt(key, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(out), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key []byte, hexCiphertext string) ([]byte, error) {
	if hexCiphertext == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return nil, fmt.Errorf("repo password hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext shorter than nonce")
	}
	return aead.Open(nil, raw[:ns], raw[ns:], nil)
}
