// Package seal encrypts small values an application must be able to read
// back, such as third-party client secrets, private keys or values in a
// cookie, using AES-256-GCM.
//
// A sealed value is the random nonce followed by the ciphertext and the GCM
// tag:
//
//	nonce (12 bytes) | ciphertext | tag (16 bytes)
//
// Every value is bound to a purpose (for example "totp:<user-id>"). The
// purpose is authenticated but not stored, so a sealed value only opens with
// the purpose it was sealed for and cannot be moved to another place.
//
// Nonces are random. With a 96 bit nonce a single key should seal fewer than
// 2^32 values; for longer lived keys, rotate.
//
// Typical usage:
//
//	s, err := seal.New(key) // 32 bytes
//	if err != nil { ... }
//
//	sealed := s.Seal([]byte("secret"), "provider:42")
//	plain, err := s.Open(sealed, "provider:42")
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the size of the key New expects.
const KeySize = 32

// Overhead is the number of bytes Seal adds to a value.
const Overhead = 12 + 16

var (
	// ErrKeySize is returned by New when the key is not KeySize bytes.
	ErrKeySize = errors.New("seal: key must be 32 bytes")

	// ErrOpen is returned by Open when a value is too short, was altered,
	// was sealed with another key or for another purpose.
	ErrOpen = errors.New("seal: cannot open value")
)

// Sealer seals and opens values with one key. It is safe for concurrent use.
type Sealer struct {
	aead cipher.AEAD
}

// New returns a Sealer for a KeySize byte key. Returns ErrKeySize otherwise.
func New(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w, got %d", ErrKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Sealer{aead: aead}, nil
}

// Seal encrypts plain and binds the result to purpose.
func (s *Sealer) Seal(plain []byte, purpose string) []byte {
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	rand.Read(nonce) // Never returns an error.

	return s.aead.Seal(nonce, nonce, plain, []byte(purpose))
}

// Open decrypts a value sealed for purpose. Returns ErrOpen if the value
// cannot be opened.
func (s *Sealer) Open(sealed []byte, purpose string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n+s.aead.Overhead() {
		return nil, ErrOpen
	}

	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(purpose))
	if err != nil {
		return nil, ErrOpen
	}

	return plain, nil
}
