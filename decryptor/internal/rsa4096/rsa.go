package rsa4096

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)


func DecryptWithRSA4096(ciphertext []byte, privateKeyBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key" + err.Error())
	}

	// Decrypt the ciphertext with the private key
	plaintextBytes, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		ciphertext,
		nil)
	if err != nil {
		return nil, errors.New("failed to decrypt with RSA: " + err.Error())
	}

	// Return the plaintext bytes
	return plaintextBytes, nil
}