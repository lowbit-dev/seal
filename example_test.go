package seal

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Example demonstrates sealing a value and opening it again.
func Example() {
	key := make([]byte, KeySize)
	rand.Read(key)

	s, err := New(key)
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
	s, _ := New(make([]byte, KeySize))

	sealed := s.Seal([]byte("secret"), "totp:alice")

	_, err := s.Open(sealed, "totp:bob")
	fmt.Println(errors.Is(err, ErrOpen))
	// Output: true
}
