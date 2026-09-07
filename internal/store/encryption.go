package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const encryptedFieldPrefix = "enc:v1:"

type DatastoreEncryptor struct {
	key []byte
}

func NewDatastoreEncryptorKey(key []byte) (*DatastoreEncryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("datastore encryption requires a 32-byte AES-256 key")
	}
	return &DatastoreEncryptor{key: append([]byte(nil), key...)}, nil
}

func NewDatastoreEncryptor(hexKey string) (*DatastoreEncryptor, error) {
	if hexKey == "" {
		return nil, errors.New("a 256-bit hex encryption key is required; generated in-memory keys are not recoverable")
	}
	k, err := hex.DecodeString(hexKey)
	if err != nil || len(k) != 32 {
		return nil, errors.New("invalid 256-bit hex encryption key")
	}
	return &DatastoreEncryptor{key: k}, nil
}

// SealString uses authenticated deterministic encryption so existing equality
// constraints and deduplication remain functional. It reveals equality within
// a single column domain, but neither plaintext nor cross-domain equality.
func (e *DatastoreEncryptor) SealString(domain, plaintext string) (string, error) {
	if plaintext == "" || strings.HasPrefix(plaintext, encryptedFieldPrefix) {
		return plaintext, nil
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, e.key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(plaintext))
	nonce := mac.Sum(nil)[:gcm.NonceSize()]
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), []byte(domain))
	payload := append(append([]byte(nil), nonce...), ciphertext...)
	return encryptedFieldPrefix + base64.RawStdEncoding.EncodeToString(payload), nil
}

func (e *DatastoreEncryptor) OpenString(domain, value string) (string, error) {
	if value == "" || !strings.HasPrefix(value, encryptedFieldPrefix) {
		return value, nil
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, encryptedFieldPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted datastore field: %w", err)
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("encrypted datastore field is malformed")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte(domain))
	if err != nil {
		return "", fmt.Errorf("authenticate encrypted datastore field: %w", err)
	}
	return string(plaintext), nil
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
