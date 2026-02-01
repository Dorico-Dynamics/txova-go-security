// Package password provides secure password hashing using Argon2id.
//
// Argon2id is the winner of the Password Hashing Competition and provides
// resistance against both GPU-based and side-channel attacks.
//
// Default parameters follow OWASP recommendations:
//   - Memory: 64 MB
//   - Iterations: 3
//   - Parallelism: 4
//   - Salt length: 16 bytes
//   - Key length: 32 bytes
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
	"golang.org/x/crypto/argon2"
)

// Default Argon2id parameters per OWASP recommendations.
const (
	DefaultMemory      uint32 = 64 * 1024 // 64 MB in KiB
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 4
	DefaultSaltLength  uint32 = 16
	DefaultKeyLength   uint32 = 32

	// Password length constraints.
	MinPasswordLength = 8
	MaxPasswordLength = 128
)

// Config holds Argon2id configuration parameters.
type Config struct {
	// Memory is the amount of memory used in KiB.
	Memory uint32
	// Iterations is the number of iterations (time cost).
	Iterations uint32
	// Parallelism is the number of threads to use.
	Parallelism uint8
	// SaltLength is the length of the random salt in bytes.
	SaltLength uint32
	// KeyLength is the length of the generated key in bytes.
	KeyLength uint32
}

// DefaultConfig returns the default Argon2id configuration per OWASP recommendations.
func DefaultConfig() Config {
	return Config{
		Memory:      DefaultMemory,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
		SaltLength:  DefaultSaltLength,
		KeyLength:   DefaultKeyLength,
	}
}

// Hasher provides password hashing and verification using Argon2id.
type Hasher struct {
	config Config
}

// New creates a new Hasher with the given configuration.
// Zero values in the config are replaced with defaults.
func New(cfg Config) *Hasher {
	if cfg.Memory == 0 {
		cfg.Memory = DefaultMemory
	}
	if cfg.Iterations == 0 {
		cfg.Iterations = DefaultIterations
	}
	if cfg.Parallelism == 0 {
		cfg.Parallelism = DefaultParallelism
	}
	if cfg.SaltLength == 0 {
		cfg.SaltLength = DefaultSaltLength
	}
	if cfg.KeyLength == 0 {
		cfg.KeyLength = DefaultKeyLength
	}
	return &Hasher{config: cfg}
}

// NewDefault creates a new Hasher with default configuration.
func NewDefault() *Hasher {
	return New(DefaultConfig())
}

// NewWithOptions creates a Hasher with functional options.
func NewWithOptions(opts ...Option) *Hasher {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return New(cfg)
}

// Option configures a Hasher.
type Option func(*Config)

// WithMemory sets the memory parameter in KiB.
func WithMemory(memory uint32) Option {
	return func(c *Config) {
		c.Memory = memory
	}
}

// WithIterations sets the time cost parameter.
func WithIterations(iterations uint32) Option {
	return func(c *Config) {
		c.Iterations = iterations
	}
}

// WithParallelism sets the parallelism factor.
func WithParallelism(parallelism uint8) Option {
	return func(c *Config) {
		c.Parallelism = parallelism
	}
}

// WithSaltLength sets the salt length in bytes.
func WithSaltLength(length uint32) Option {
	return func(c *Config) {
		c.SaltLength = length
	}
}

// WithKeyLength sets the hash length in bytes.
func WithKeyLength(length uint32) Option {
	return func(c *Config) {
		c.KeyLength = length
	}
}

// Hash generates an Argon2id hash from the given password.
// Returns a PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
//
// The context parameter is reserved for future use (e.g., cancellation).
func (h *Hasher) Hash(_ context.Context, password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	// Generate cryptographically secure random salt
	salt := make([]byte, h.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.InternalErrorWrap("failed to generate salt", err)
	}

	// Generate hash using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.config.Iterations,
		h.config.Memory,
		h.config.Parallelism,
		h.config.KeyLength,
	)

	// Encode as PHC string format
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.config.Memory,
		h.config.Iterations,
		h.config.Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

// Verify compares a password against an encoded hash.
// Uses constant-time comparison to prevent timing attacks.
//
// The context parameter is reserved for future use (e.g., cancellation).
func (h *Hasher) Verify(_ context.Context, password, encodedHash string) (bool, error) {
	if password == "" {
		return false, ErrEmptyPassword
	}
	if encodedHash == "" {
		return false, ErrInvalidHash
	}

	// Parse the encoded hash
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Generate hash with the same parameters from the stored hash.
	// Hash length is bounded by base64 decoding (max ~1KB for reasonable hashes).
	hashLen := len(hash)
	if hashLen > 1024 {
		return false, ErrInvalidHash
	}
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		uint32(hashLen), // #nosec G115 -- bounded by check above
	)

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// NeedsRehash checks if the hash was created with different parameters
// and should be rehashed on next successful login.
func (h *Hasher) NeedsRehash(encodedHash string) (bool, error) {
	if encodedHash == "" {
		return false, ErrInvalidHash
	}

	params, _, _, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	return params.Memory != h.config.Memory ||
		params.Iterations != h.config.Iterations ||
		params.Parallelism != h.config.Parallelism, nil
}

// Config returns the current configuration.
func (h *Hasher) Config() Config {
	return h.config
}

// decodeHash parses a PHC-formatted Argon2id hash string.
func decodeHash(encodedHash string) (*Config, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	// parts[0] is empty (before first $)
	// parts[1] is "argon2id"
	// parts[2] is "v=19"
	// parts[3] is "m=65536,t=3,p=4"
	// parts[4] is base64 salt
	// parts[5] is base64 hash

	if parts[1] != "argon2id" {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	// Validate reasonable bounds for salt and hash lengths.
	// Typical values: salt=16 bytes, hash=32 bytes. Max 1KB is very generous.
	if len(salt) > 1024 || len(hash) > 1024 {
		return nil, nil, nil, ErrInvalidHash
	}

	return &Config{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  uint32(len(salt)), // #nosec G115 -- bounded by check above
		KeyLength:   uint32(len(hash)), // #nosec G115 -- bounded by check above
	}, salt, hash, nil
}

// ParseConfigFromHash extracts configuration from an existing hash.
// Useful for migration scenarios or parameter analysis.
func ParseConfigFromHash(encodedHash string) (*Config, error) {
	params, _, _, err := decodeHash(encodedHash)
	return params, err
}

// ValidatePassword checks if a password meets minimum requirements.
// Returns a validation error if the password is too short or too long.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return errors.ValidationErrorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordLength {
		return errors.ValidationErrorf("password must be at most %d characters", MaxPasswordLength)
	}
	return nil
}
