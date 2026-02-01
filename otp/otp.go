// Package otp provides secure OTP (One-Time Password) generation and verification
// with Redis-backed storage, rate limiting, and lockout protection.
package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/Dorico-Dynamics/txova-go-core/logging"
	"github.com/Dorico-Dynamics/txova-go-types/contact"

	secerrors "github.com/Dorico-Dynamics/txova-go-security"
	"github.com/Dorico-Dynamics/txova-go-security/mask"
)

// RedisClient defines the interface for Redis operations required by the OTP service.
// This interface is compatible with go-redis/v9 Client.
type RedisClient interface {
	Get(ctx context.Context, key string) StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) StatusCmd
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) BoolCmd
	Del(ctx context.Context, keys ...string) IntCmd
	Incr(ctx context.Context, key string) IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) BoolCmd
	Exists(ctx context.Context, keys ...string) IntCmd
}

// StringCmd is the interface for Redis string command results.
type StringCmd interface {
	Result() (string, error)
}

// StatusCmd is the interface for Redis status command results.
type StatusCmd interface {
	Err() error
}

// BoolCmd is the interface for Redis bool command results.
type BoolCmd interface {
	Result() (bool, error)
}

// IntCmd is the interface for Redis int command results.
type IntCmd interface {
	Result() (int64, error)
}

// Config holds the configuration for the OTP service.
type Config struct {
	// Length is the number of digits in the OTP (default: 6).
	Length int
	// Expiry is the OTP validity duration (default: 5m).
	Expiry time.Duration
	// MaxAttempts is the maximum verification attempts before lockout (default: 3).
	MaxAttempts int
	// LockoutDuration is how long the account is locked after max attempts (default: 15m).
	LockoutDuration time.Duration
	// Cooldown is the minimum time between OTP generation requests (default: 60s).
	Cooldown time.Duration
	// KeyPrefix is the prefix for Redis keys (default: "otp").
	KeyPrefix string
}

// DefaultConfig returns the default OTP configuration.
func DefaultConfig() Config {
	return Config{
		Length:          6,
		Expiry:          5 * time.Minute,
		MaxAttempts:     3,
		LockoutDuration: 15 * time.Minute,
		Cooldown:        60 * time.Second,
		KeyPrefix:       "otp",
	}
}

// Option is a functional option for configuring the OTP service.
type Option func(*Service)

// WithLength sets the OTP length.
func WithLength(length int) Option {
	return func(s *Service) {
		if length > 0 && length <= 10 {
			s.config.Length = length
		}
	}
}

// WithExpiry sets the OTP expiry duration.
func WithExpiry(expiry time.Duration) Option {
	return func(s *Service) {
		if expiry > 0 {
			s.config.Expiry = expiry
		}
	}
}

// WithMaxAttempts sets the maximum verification attempts.
func WithMaxAttempts(maxAttempts int) Option {
	return func(s *Service) {
		if maxAttempts > 0 {
			s.config.MaxAttempts = maxAttempts
		}
	}
}

// WithLockoutDuration sets the lockout duration.
func WithLockoutDuration(duration time.Duration) Option {
	return func(s *Service) {
		if duration > 0 {
			s.config.LockoutDuration = duration
		}
	}
}

// WithCooldown sets the cooldown duration between OTP requests.
// Use duration <= 0 to disable cooldown.
func WithCooldown(duration time.Duration) Option {
	return func(s *Service) {
		if duration <= 0 {
			s.config.Cooldown = 0
		} else {
			s.config.Cooldown = duration
		}
	}
}

// WithKeyPrefix sets the Redis key prefix.
func WithKeyPrefix(prefix string) Option {
	return func(s *Service) {
		if prefix != "" {
			s.config.KeyPrefix = prefix
		}
	}
}

// WithLogger sets the logger for the service.
func WithLogger(logger *logging.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// Service provides OTP generation and verification with Redis storage.
type Service struct {
	redis  RedisClient
	config Config
	logger *logging.Logger
}

// New creates a new OTP service with the given Redis client and options.
func New(redis RedisClient, opts ...Option) *Service {
	s := &Service{
		redis:  redis,
		config: DefaultConfig(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Generate creates a new OTP for the given phone number.
// Returns the plaintext OTP (for SMS sending) and the expiry time.
// The OTP is stored as a SHA256 hash in Redis.
func (s *Service) Generate(ctx context.Context, phone contact.PhoneNumber) (string, time.Time, error) {
	phoneStr := phone.String()

	// Check cooldown (skip if cooldown is disabled).
	if s.config.Cooldown > 0 {
		cooldownKey := s.key("cooldown", phoneStr)
		exists, err := s.redis.Exists(ctx, cooldownKey).Result()
		if err != nil {
			s.log(ctx, "error", "Redis error checking cooldown", "phone", mask.Phone(phoneStr), "error", err)
			return "", time.Time{}, fmt.Errorf("failed to check cooldown: %w", err)
		}
		if exists > 0 {
			s.log(ctx, "warn", "OTP cooldown active", "phone", mask.Phone(phoneStr))
			return "", time.Time{}, secerrors.OTPCooldown()
		}
	}

	// Generate OTP
	otp, err := s.generateCode()
	if err != nil {
		return "", time.Time{}, err
	}

	// Hash the OTP for storage
	hashedOTP := hashOTP(otp)
	expiry := time.Now().Add(s.config.Expiry)

	// Store hashed OTP
	otpKey := s.key("code", phoneStr)
	if err := s.redis.Set(ctx, otpKey, hashedOTP, s.config.Expiry).Err(); err != nil {
		return "", time.Time{}, secerrors.OTPCooldown()
	}

	// Set cooldown (skip if cooldown is disabled).
	if s.config.Cooldown > 0 {
		cooldownKey := s.key("cooldown", phoneStr)
		if err := s.redis.Set(ctx, cooldownKey, "1", s.config.Cooldown).Err(); err != nil {
			// Log but don't fail - OTP was already generated.
			s.log(ctx, "warn", "Failed to set cooldown", "phone", mask.Phone(phoneStr))
		}
	}

	s.log(ctx, "info", "OTP generated", "phone", mask.Phone(phoneStr), "expiry", expiry.Format(time.RFC3339))

	return otp, expiry, nil
}

// Verify checks if the provided OTP is valid for the given phone number.
// Returns nil on success, or an error describing the failure.
func (s *Service) Verify(ctx context.Context, phone contact.PhoneNumber, code string) error {
	phoneStr := phone.String()

	// Check lockout first
	locked, err := s.IsLocked(ctx, phone)
	if err != nil {
		return err
	}
	if locked {
		s.log(ctx, "warn", "OTP verification blocked - account locked", "phone", mask.Phone(phoneStr))
		return secerrors.OTPLocked()
	}

	// Increment attempt counter
	attemptsKey := s.key("attempts", phoneStr)
	attempts, err := s.redis.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return secerrors.OTPInvalid()
	}

	// Set expiry on attempts key if it's the first attempt
	if attempts == 1 {
		_ = s.redis.Expire(ctx, attemptsKey, s.config.LockoutDuration)
	}

	// Check if max attempts exceeded
	if int(attempts) > s.config.MaxAttempts {
		// Set lockout
		lockoutKey := s.key("lockout", phoneStr)
		_ = s.redis.Set(ctx, lockoutKey, "1", s.config.LockoutDuration)
		s.log(ctx, "warn", "Account locked due to too many attempts", "phone", mask.Phone(phoneStr))
		return secerrors.OTPLocked()
	}

	// Get stored OTP hash
	otpKey := s.key("code", phoneStr)
	storedHash, err := s.redis.Get(ctx, otpKey).Result()
	if err != nil {
		s.log(ctx, "info", "OTP verification failed - no OTP found", "phone", mask.Phone(phoneStr))
		return secerrors.OTPInvalid()
	}

	// Compare hashes
	providedHash := hashOTP(code)
	if storedHash != providedHash {
		s.log(ctx, "info", "OTP verification failed - invalid code", "phone", mask.Phone(phoneStr), "attempts", attempts)
		return secerrors.OTPInvalid()
	}

	// Success - clean up
	_ = s.redis.Del(ctx, otpKey, attemptsKey)

	s.log(ctx, "info", "OTP verified successfully", "phone", mask.Phone(phoneStr))

	return nil
}

// IsLocked checks if the phone number is currently locked out.
func (s *Service) IsLocked(ctx context.Context, phone contact.PhoneNumber) (bool, error) {
	lockoutKey := s.key("lockout", phone.String())
	exists, err := s.redis.Exists(ctx, lockoutKey).Result()
	if err != nil {
		return false, secerrors.OTPInvalid()
	}
	return exists > 0, nil
}

// GetAttempts returns the current number of failed verification attempts.
func (s *Service) GetAttempts(ctx context.Context, phone contact.PhoneNumber) int {
	attemptsKey := s.key("attempts", phone.String())
	result, err := s.redis.Get(ctx, attemptsKey).Result()
	if err != nil {
		// No attempts recorded
		return 0
	}
	attempts, err := strconv.Atoi(result)
	if err != nil {
		return 0
	}
	return attempts
}

// Invalidate removes any existing OTP for the phone number.
func (s *Service) Invalidate(ctx context.Context, phone contact.PhoneNumber) error {
	phoneStr := phone.String()
	otpKey := s.key("code", phoneStr)
	_, err := s.redis.Del(ctx, otpKey).Result()
	if err != nil {
		return secerrors.OTPInvalid()
	}
	s.log(ctx, "info", "OTP invalidated", "phone", mask.Phone(phoneStr))
	return nil
}

// key generates a Redis key with the configured prefix.
func (s *Service) key(keyType, phone string) string {
	return fmt.Sprintf("%s:%s:%s", s.config.KeyPrefix, keyType, phone)
}

// generateCode generates a random numeric OTP of the configured length.
func (s *Service) generateCode() (string, error) {
	maxValue := new(big.Int)
	maxValue.Exp(big.NewInt(10), big.NewInt(int64(s.config.Length)), nil)

	n, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return "", secerrors.OTPInvalid()
	}

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", s.config.Length)
	return fmt.Sprintf(format, n.Int64()), nil
}

// hashOTP creates a SHA256 hash of the OTP.
func hashOTP(otp string) string {
	hash := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(hash[:])
}

// log logs a message if a logger is configured.
func (s *Service) log(ctx context.Context, level, msg string, args ...any) {
	if s.logger == nil {
		return
	}

	switch level {
	case "info":
		s.logger.InfoContext(ctx, msg, args...)
	case "warn":
		s.logger.WarnContext(ctx, msg, args...)
	case "error":
		s.logger.ErrorContext(ctx, msg, args...)
	}
}
