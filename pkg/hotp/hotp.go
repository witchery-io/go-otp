package hotp

import (
	"hash"

	"github.com/witchery-io/go-otp/pkg/otp"
)

type HOTP struct {
	*otp.Base
}

// New HOTP instance
func New(secret string, digits int, hasher func() hash.Hash) otp.OTP {
	return &HOTP{Base: otp.New(secret, digits, hasher)}
}
