package totp

import (
	"hash"

	"github.com/witchery-io/go-otp/pkg/otp"
)

type TOTP struct {
	*otp.Base
}

// New TOTP instance
func New(secret string, digits int, hasher func() hash.Hash) otp.OTP {
	return &TOTP{Base: otp.New(secret, digits, hasher)}
}
