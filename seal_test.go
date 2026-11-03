package seal

import (
	"bytes"
	"errors"
	"testing"
)

// mustNew creates a Sealer for use in tests, failing immediately on error.
func mustNew(t testing.TB, key []byte) *Sealer {
	t.Helper()
	s, err := New(key)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	return s
}

func key(b byte) []byte {
	return bytes.Repeat([]byte{b}, KeySize)
}

func TestNew_KeySize(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := New(make([]byte, n)); !errors.Is(err, ErrKeySize) {
			t.Errorf("New(%d bytes): got %v, want ErrKeySize", n, err)
		}
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	s := mustNew(t, key(1))
	for _, plain := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte("abc"), 1000)} {
		sealed := s.Seal(plain, "p")
		if len(sealed) != len(plain)+Overhead {
			t.Errorf("len(sealed) = %d, want %d", len(sealed), len(plain)+Overhead)
		}
		got, err := s.Open(sealed, "p")
		if err != nil {
			t.Fatalf("Open: unexpected error: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("Open = %q, want %q", got, plain)
		}
	}
}

func TestSeal_RandomNonce(t *testing.T) {
	s := mustNew(t, key(1))
	if bytes.Equal(s.Seal([]byte("x"), "p"), s.Seal([]byte("x"), "p")) {
		t.Error("sealing the same value twice gave the same result")
	}
}

func TestOpen_Rejects(t *testing.T) {
	s := mustNew(t, key(1))
	sealed := s.Seal([]byte("secret"), "p")

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1

	cases := map[string]struct {
		s       *Sealer
		sealed  []byte
		purpose string
	}{
		"other purpose": {s, sealed, "q"},
		"other key":     {mustNew(t, key(2)), sealed, "p"},
		"tampered":      {s, tampered, "p"},
		"truncated":     {s, sealed[:Overhead-1], "p"},
		"empty":         {s, nil, "p"},
	}
	for name, c := range cases {
		if _, err := c.s.Open(c.sealed, c.purpose); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: got %v, want ErrOpen", name, err)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	s := mustNew(b, key(1))
	plain := make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		s.Seal(plain, "purpose")
	}
}

func BenchmarkOpen(b *testing.B) {
	s := mustNew(b, key(1))
	sealed := s.Seal(make([]byte, 64), "purpose")
	b.ReportAllocs()
	for b.Loop() {
		s.Open(sealed, "purpose")
	}
}
