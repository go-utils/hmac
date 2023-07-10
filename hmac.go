package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
)

//go:generate mockgen -source=$GOFILE -destination=./hmacmock/mock_$GOFILE -package=hmacmock

// Verifier - verifier
type Verifier interface {
	Do(message, messageMAC []byte) error
}

type verifier struct {
	secretKey []byte
}

// NewVerifier - constructor
func NewVerifier(secretKey []byte) Verifier {
	return &verifier{secretKey: secretKey}
}

// Do - verify
func (v *verifier) Do(message, messageMAC []byte) error {
	mac := hmac.New(sha256.New, v.secretKey)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(messageMAC, expectedMAC) {
		return NotEqual
	}

	return nil
}
