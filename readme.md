# Seal

[![Go Reference](https://pkg.go.dev/badge/lowbit.dev/seal.svg)](https://pkg.go.dev/lowbit.dev/seal) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Seal small values with AES-256-GCM.

A sealed value is a random nonce, ciphertext, and GCM tag. It is bound to a purpose string, so it can only be opened with the same purpose.

## Install

```sh
go get lowbit.dev/seal
```

## Usage

```go
s, err := seal.New(key) // 32 bytes
if err != nil {
	// ErrKeySize
}

sealed := s.Seal([]byte("client secret"), "provider:42")
plain, err := s.Open(sealed, "provider:42")
if err != nil {
	// ErrOpen
}
```

The result is raw bytes. Encode it when you need a text form, such as base64.

## Errors

- `ErrKeySize`: key passed to `New` is not 32 bytes
- `ErrOpen`: value is too short, was altered, or was sealed with another key or purpose

All errors can be checked with `errors.Is`.
