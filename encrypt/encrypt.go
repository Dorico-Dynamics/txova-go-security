// Package encrypt provides AES-256-GCM encryption with key rotation support.
// It uses authenticated encryption to ensure both confidentiality and integrity.
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	secerrors "github.com/Dorico-Dynamics/txova-go-security"
)

const (
	// KeySize is the required size for AES-256 keys (32 bytes).
	KeySize = 32

	// NonceSize is the standard nonce size for GCM (12 bytes).
	NonceSize = 12

	// ciphertextSeparator separates key_id, nonce, and ciphertext in the output format.
	ciphertextSeparator = ":"
)

// Cipher provides AES-256-GCM encryption with support for multiple keys.
// The primary key is used for encryption, while all keys can be used for decryption.
// This enables key rotation without breaking existing encrypted data.
type Cipher struct {
	mu           sync.RWMutex
	primaryKeyID string
	keys         map[string][]byte
	ciphers      map[string]cipher.AEAD
}

// New creates a new Cipher with the given primary key.
// The key must be exactly 32 bytes for AES-256.
func New(primaryKeyID string, primaryKey []byte) (*Cipher, error) {
	if primaryKeyID == "" {
		return nil, secerrors.InvalidKey("key ID cannot be empty")
	}

	if len(primaryKey) != KeySize {
		return nil, secerrors.InvalidKey(fmt.Sprintf("key must be %d bytes, got %d", KeySize, len(primaryKey)))
	}

	c := &Cipher{
		primaryKeyID: primaryKeyID,
		keys:         make(map[string][]byte),
		ciphers:      make(map[string]cipher.AEAD),
	}

	if err := c.addKeyInternal(primaryKeyID, primaryKey); err != nil {
		return nil, err
	}

	return c, nil
}

// AddKey adds a new key for decryption. This enables key rotation.
// After adding a new key, you can set it as primary with SetPrimaryKey.
func (c *Cipher) AddKey(keyID string, key []byte) error {
	if keyID == "" {
		return secerrors.InvalidKey("key ID cannot be empty")
	}

	if len(key) != KeySize {
		return secerrors.InvalidKey(fmt.Sprintf("key must be %d bytes, got %d", KeySize, len(key)))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key ID already exists.
	if _, exists := c.keys[keyID]; exists {
		return secerrors.InvalidKey(fmt.Sprintf("key %q already exists", keyID))
	}

	return c.addKeyInternal(keyID, key)
}

// addKeyInternal adds a key without locking (caller must hold lock).
func (c *Cipher) addKeyInternal(keyID string, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return secerrors.EncryptionFailed(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return secerrors.EncryptionFailed(err)
	}

	// Store a copy of the key
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	c.keys[keyID] = keyCopy
	c.ciphers[keyID] = gcm

	return nil
}

// SetPrimaryKey changes the primary key used for encryption.
// The key must have been previously added with AddKey.
func (c *Cipher) SetPrimaryKey(keyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.ciphers[keyID]; !ok {
		return secerrors.InvalidKey(fmt.Sprintf("key %q not found", keyID))
	}

	c.primaryKeyID = keyID
	return nil
}

// Encrypt encrypts the plaintext using AES-256-GCM.
// Returns the ciphertext in format: {key_id}:{nonce_base64}:{ciphertext_base64}.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	c.mu.RLock()
	gcm := c.ciphers[c.primaryKeyID]
	keyID := c.primaryKeyID
	c.mu.RUnlock()

	// Generate a unique nonce for each encryption
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", secerrors.EncryptionFailed(err)
	}

	// Encrypt with GCM (includes authentication tag)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: key_id:nonce_base64:ciphertext_base64
	result := fmt.Sprintf("%s%s%s%s%s",
		keyID,
		ciphertextSeparator,
		base64.RawStdEncoding.EncodeToString(nonce),
		ciphertextSeparator,
		base64.RawStdEncoding.EncodeToString(ciphertext),
	)

	return result, nil
}

// Decrypt decrypts the ciphertext and verifies its authenticity.
// The ciphertext must be in format: {key_id}:{nonce_base64}:{ciphertext_base64}.
func (c *Cipher) Decrypt(encrypted string) ([]byte, error) {
	// Parse the encrypted format
	parts := strings.SplitN(encrypted, ciphertextSeparator, 3)
	if len(parts) != 3 {
		return nil, secerrors.DecryptionFailed(nil)
	}

	keyID := parts[0]
	nonceB64 := parts[1]
	ciphertextB64 := parts[2]

	// Get the cipher for this key
	c.mu.RLock()
	gcm, ok := c.ciphers[keyID]
	c.mu.RUnlock()

	if !ok {
		return nil, secerrors.DecryptionFailed(fmt.Errorf("key %q not found", keyID))
	}

	// Decode nonce
	nonce, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, secerrors.DecryptionFailed(err)
	}

	if len(nonce) != NonceSize {
		return nil, secerrors.DecryptionFailed(fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), NonceSize))
	}

	// Decode ciphertext
	ciphertext, err := base64.RawStdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, secerrors.DecryptionFailed(err)
	}

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, secerrors.DecryptionFailed(err)
	}

	return plaintext, nil
}

// EncryptField encrypts a string field for storage.
// Returns empty string for empty input without error.
func (c *Cipher) EncryptField(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return c.Encrypt([]byte(value))
}

// DecryptField decrypts an encrypted string field.
// Returns empty string for empty input without error.
func (c *Cipher) DecryptField(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	plaintext, err := c.Decrypt(encrypted)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// PrimaryKeyID returns the current primary key ID.
func (c *Cipher) PrimaryKeyID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.primaryKeyID
}

// HasKey checks if a key with the given ID exists.
func (c *Cipher) HasKey(keyID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.ciphers[keyID]
	return ok
}

// KeyIDs returns all registered key IDs.
func (c *Cipher) KeyIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make([]string, 0, len(c.ciphers))
	for id := range c.ciphers {
		ids = append(ids, id)
	}
	return ids
}

// GenerateKey generates a cryptographically secure random key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, secerrors.EncryptionFailed(err)
	}
	return key, nil
}
