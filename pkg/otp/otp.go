package otp

import (
	"bytes"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strconv"
	"strings"
)

type OTP interface {
	At(counter int64) (string, error)
	Verify(otp string, counter int64) (bool, error)
}

type Base struct {
	hash   func() hash.Hash
	secret string
	digits int
}

func (b *Base) At(counter int64) (string, error) {
	return b.generateOTP(counter)
}

func (b *Base) Verify(otp string, counter int64) (bool, error) {
	gOTP, err := b.generateOTP(counter)
	if err != nil {
		return false, err
	}
	return gOTP == otp, nil
}

func (b *Base) generateOTP(counter int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(b.secret))
	if err != nil {
		return "", err
	}
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(counter))

	hs := hmac.New(b.hash, key)
	hs.Write(bs)
	h := hs.Sum(nil)

	o := h[19] & 15

	var header uint32

	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return "", err
	}

	h12 := (int(header) & 0x7fffffff) % 1000000

	otp := strconv.Itoa(h12)

	return b.prefix0(otp), nil
}

func (b *Base) prefix0(otp string) string {
	if len(otp) == 6 {
		return otp
	}
	for i := 6 - len(otp); i > 0; i-- {
		otp = "0" + otp
	}
	return otp
}
