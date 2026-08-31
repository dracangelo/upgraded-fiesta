package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type DatastoreEncryptor struct {
	key []byte
}

func NewDatastoreEncryptor(hexKey string) (*DatastoreEncryptor, error) {
	if hexKey == "" {
		// Generate 256-bit key if not provided
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("failed to generate random key: %w", err)
		}
		return &DatastoreEncryptor{key: k}, nil
	}
	k, err := hex.DecodeString(hexKey)
	if err != nil || len(k) != 32 {
		return nil, errors.New("invalid 256-bit hex encryption key")
	}
	return &DatastoreEncryptor{key: k}, nil
}

func (e *DatastoreEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (e *DatastoreEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
