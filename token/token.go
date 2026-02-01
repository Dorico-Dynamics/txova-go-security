// Package token provides secure random token generation for sessions, API keys, and more.
//
// All token generation uses crypto/rand exclusively for cryptographically secure randomness.
// Tokens can be generated in hex or URL-safe base64 encoding.
//
// Important: Never store plaintext tokens. Always store the hash using Hash().
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

// Standard token lengths in bytes.
const (
	// SessionTokenBytes is the length for session tokens.
	SessionTokenBytes = 32
	// RefreshTokenBytes is the length for refresh tokens.
	RefreshTokenBytes = 32
	// ResetTokenBytes is the length for password reset tokens.
	ResetTokenBytes = 32
	// VerificationTokenBytes is the length for email verification tokens.
	VerificationTokenBytes = 32
	// APIKeyBytes is the length for API keys.
	APIKeyBytes = 32

	// MinTokenBytes is the minimum allowed token length.
	MinTokenBytes = 16
	// MaxTokenBytes is the maximum allowed token length.
	MaxTokenBytes = 256
)

// Generate creates a cryptographically secure random token.
// Returns a 32-byte (256-bit) token encoded as hex string (64 characters).
func Generate() (string, error) {
	return GenerateWithLength(SessionTokenBytes)
}

// GenerateWithLength creates a random token with the specified number of bytes.
// Returns the token encoded as hex string (2 characters per byte).
func GenerateWithLength(bytes int) (string, error) {
	if bytes < MinTokenBytes {
		return "", errors.ValidationErrorf("token length must be at least %d bytes", MinTokenBytes)
	}
	if bytes > MaxTokenBytes {
		return "", errors.ValidationErrorf("token length must be at most %d bytes", MaxTokenBytes)
	}

	token := make([]byte, bytes)
	if _, err := rand.Read(token); err != nil {
		return "", errors.InternalErrorWrap("failed to generate random token", err)
	}

	return hex.EncodeToString(token), nil
}

// GenerateURLSafe creates a cryptographically secure random token suitable for URLs.
// Returns a 32-byte (256-bit) token encoded as URL-safe base64 (no padding).
func GenerateURLSafe() (string, error) {
	return GenerateURLSafeWithLength(SessionTokenBytes)
}

// GenerateURLSafeWithLength creates a URL-safe random token with the specified bytes.
// Returns the token encoded as URL-safe base64 without padding.
func GenerateURLSafeWithLength(bytes int) (string, error) {
	if bytes < MinTokenBytes {
		return "", errors.ValidationErrorf("token length must be at least %d bytes", MinTokenBytes)
	}
	if bytes > MaxTokenBytes {
		return "", errors.ValidationErrorf("token length must be at most %d bytes", MaxTokenBytes)
	}

	token := make([]byte, bytes)
	if _, err := rand.Read(token); err != nil {
		return "", errors.InternalErrorWrap("failed to generate random token", err)
	}

	return base64.RawURLEncoding.EncodeToString(token), nil
}

// GenerateBytes creates a cryptographically secure random byte slice.
// Returns raw bytes, useful when you need to control the encoding yourself.
func GenerateBytes(length int) ([]byte, error) {
	if length < MinTokenBytes {
		return nil, errors.ValidationErrorf("token length must be at least %d bytes", MinTokenBytes)
	}
	if length > MaxTokenBytes {
		return nil, errors.ValidationErrorf("token length must be at most %d bytes", MaxTokenBytes)
	}

	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return nil, errors.InternalErrorWrap("failed to generate random bytes", err)
	}

	return token, nil
}

// Type-specific token generators for clarity.

// GenerateSessionToken creates a token suitable for user sessions.
func GenerateSessionToken() (string, error) {
	return GenerateWithLength(SessionTokenBytes)
}

// GenerateRefreshToken creates a token suitable for JWT refresh tokens.
func GenerateRefreshToken() (string, error) {
	return GenerateWithLength(RefreshTokenBytes)
}

// GenerateResetToken creates a URL-safe token for password reset links.
func GenerateResetToken() (string, error) {
	return GenerateURLSafeWithLength(ResetTokenBytes)
}

// GenerateVerificationToken creates a URL-safe token for email verification links.
func GenerateVerificationToken() (string, error) {
	return GenerateURLSafeWithLength(VerificationTokenBytes)
}

// GenerateAPIKey creates a token suitable for API authentication.
func GenerateAPIKey() (string, error) {
	return GenerateWithLength(APIKeyBytes)
}

// Hashing functions for secure token storage.

// Hash returns the SHA-256 hash of a token, encoded as hex.
// Use this to store tokens securely - never store plaintext tokens.
func Hash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashBytes returns the SHA-256 hash of raw bytes, encoded as hex.
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Compare securely compares a plaintext token against a stored hash.
// Uses constant-time comparison to prevent timing attacks.
func Compare(token, hashedToken string) bool {
	tokenHash := Hash(token)
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(hashedToken)) == 1
}

// CompareBytes securely compares raw token bytes against a stored hash.
func CompareBytes(token []byte, hashedToken string) bool {
	tokenHash := HashBytes(token)
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(hashedToken)) == 1
}

// IsValidHexToken checks if a string is a valid hex-encoded token.
func IsValidHexToken(token string, expectedBytes int) bool {
	if len(token) != expectedBytes*2 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// IsValidBase64Token checks if a string is a valid URL-safe base64 token.
func IsValidBase64Token(token string, expectedBytes int) bool {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	return len(data) == expectedBytes
}
