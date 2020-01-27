package util

import (
	"crypto/rand"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateSecret(length int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}
