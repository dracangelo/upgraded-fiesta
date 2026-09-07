package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	encryptedBackupMagic = "enumscan-encrypted-backup-v1\x00"
	backupChunkSize      = 64 * 1024
)

// DecodeBackupKey accepts the base64-encoded 32-byte AES-256 key stored in an
// operator-provided environment variable. The value is never persisted.
func DecodeBackupKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("encrypted backup key must be a base64-encoded 32-byte AES-256 key")
	}
	return key, nil
}

// BackupEncrypted writes an AES-256-GCM authenticated, chunked snapshot. The
// live SQLite database remains unencrypted; this protects explicitly created
// backup artifacts without introducing a simulated datastore-encryption claim.
func (s *SQLiteCLI) BackupEncrypted(ctx context.Context, targetPath string, key []byte) error {
	if _, err := encryptedBackupGCM(key); err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create encrypted backup directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("restrict encrypted backup directory permissions: %w", err)
	}
	snapshot, err := os.CreateTemp(dir, ".enumscan-backup-snapshot-*")
	if err != nil {
		return fmt.Errorf("create temporary backup snapshot: %w", err)
	}
	snapshotPath := snapshot.Name()
	if err := snapshot.Close(); err != nil {
		_ = os.Remove(snapshotPath)
		return fmt.Errorf("close temporary backup snapshot: %w", err)
	}
	if err := os.Remove(snapshotPath); err != nil {
		return fmt.Errorf("prepare temporary backup snapshot: %w", err)
	}
	defer func() { _ = os.Remove(snapshotPath) }()
	if err := s.Backup(ctx, snapshotPath); err != nil {
		return fmt.Errorf("create encrypted backup snapshot: %w", err)
	}
	if err := encryptBackupFile(snapshotPath, targetPath, key); err != nil {
		return fmt.Errorf("encrypt backup snapshot: %w", err)
	}
	return nil
}

// RestoreEncrypted authenticates and decrypts an encrypted backup before using
// the normal restore path. Callers must make restore an explicit operator
// action because it overwrites the local database.
func (s *SQLiteCLI) RestoreEncrypted(ctx context.Context, backupPath string, key []byte) error {
	if _, err := encryptedBackupGCM(key); err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create restore directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("restrict restore directory permissions: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".enumscan-restore-snapshot-*")
	if err != nil {
		return fmt.Errorf("create temporary restore snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close temporary restore snapshot: %w", err)
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := decryptBackupFile(backupPath, temporaryPath, key); err != nil {
		return fmt.Errorf("decrypt backup snapshot: %w", err)
	}
	return s.Restore(ctx, temporaryPath)
}

func encryptedBackupGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encrypted backup requires a 32-byte AES-256 key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-256: %w", err)
	}
	return cipher.NewGCM(block)
}

func encryptBackupFile(sourcePath, targetPath string, key []byte) error {
	gcm, err := encryptedBackupGCM(key)
	if err != nil {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	temporary, err := os.CreateTemp(filepath.Dir(targetPath), ".enumscan-encrypted-backup-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write([]byte(encryptedBackupMagic)); err != nil {
		_ = temporary.Close()
		return err
	}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(prefix); err != nil {
		_ = temporary.Close()
		return err
	}
	buffer := make([]byte, backupChunkSize)
	var counter uint32
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			if counter == ^uint32(0) {
				_ = temporary.Close()
				return fmt.Errorf("encrypted backup is too large")
			}
			if err := writeEncryptedBackupRecord(temporary, gcm, prefix, counter, buffer[:read]); err != nil {
				_ = temporary.Close()
				return err
			}
			counter++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = temporary.Close()
			return readErr
		}
	}
	if err := writeEncryptedBackupRecord(temporary, gcm, prefix, counter, nil); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, targetPath)
}

func decryptBackupFile(sourcePath, targetPath string, key []byte) error {
	gcm, err := encryptedBackupGCM(key)
	if err != nil {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	magic := make([]byte, len(encryptedBackupMagic))
	if _, err := io.ReadFull(source, magic); err != nil || string(magic) != encryptedBackupMagic {
		return fmt.Errorf("not an enumscan encrypted backup")
	}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(source, prefix); err != nil {
		return fmt.Errorf("read encrypted backup nonce prefix: %w", err)
	}
	temporary, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer temporary.Close()
	var counter uint32
	for {
		plaintext, err := readEncryptedBackupRecord(source, gcm, prefix, counter)
		if err != nil {
			return err
		}
		if len(plaintext) == 0 {
			return temporary.Sync()
		}
		if _, err := temporary.Write(plaintext); err != nil {
			return err
		}
		counter++
	}
}

func writeEncryptedBackupRecord(writer io.Writer, gcm cipher.AEAD, prefix []byte, counter uint32, plaintext []byte) error {
	nonce, aad := encryptedBackupNonceAndAAD(prefix, counter)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	if len(ciphertext) > backupChunkSize+gcm.Overhead() {
		return fmt.Errorf("encrypted backup record is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(ciphertext)))
	if _, err := writer.Write(size[:]); err != nil {
		return err
	}
	_, err := writer.Write(ciphertext)
	return err
}

func readEncryptedBackupRecord(reader io.Reader, gcm cipher.AEAD, prefix []byte, counter uint32) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return nil, fmt.Errorf("read encrypted backup record length: %w", err)
	}
	length := binary.BigEndian.Uint32(size[:])
	if length < uint32(gcm.Overhead()) || length > backupChunkSize+uint32(gcm.Overhead()) {
		return nil, fmt.Errorf("invalid encrypted backup record length")
	}
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(reader, ciphertext); err != nil {
		return nil, fmt.Errorf("read encrypted backup record: %w", err)
	}
	nonce, aad := encryptedBackupNonceAndAAD(prefix, counter)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("authenticate encrypted backup record: %w", err)
	}
	return plaintext, nil
}

func encryptedBackupNonceAndAAD(prefix []byte, counter uint32) ([]byte, []byte) {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], counter)
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, counter)
	return nonce, aad
}
