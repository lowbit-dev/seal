package seal_test

import (
	"crypto/rand"
	"errors"
	"fmt"

	"lowbit.dev/seal"
)

// Example demonstrates sealing a value and opening it again.
func Example() {
	key := make([]byte, seal.KeySize)
	rand.Read(key)

	s, err := seal.New(key)
	if err != nil {
		panic(err)
	}

	sealed := s.Seal([]byte("client secret"), "provider:42")

	plain, err := s.Open(sealed, "provider:42")
	fmt.Println(string(plain), err)
	// Output: client secret <nil>
}

// ExampleSealer_Open_purpose shows that a value only opens for the purpose it
// was sealed for.
func ExampleSealer_Open_purpose() {
	s, _ := seal.New(make([]byte, seal.KeySize))

	sealed := s.Seal([]byte("secret"), "totp:alice")

	_, err := s.Open(sealed, "totp:bob")
	fmt.Println(errors.Is(err, seal.ErrOpen))
	// Output: true
}
