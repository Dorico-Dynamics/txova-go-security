// Package pin provides secure PIN generation and validation for ride-share applications.
// PINs are 4-digit codes used for ride verification between drivers and passengers.
package pin

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Dorico-Dynamics/txova-go-core/errors"

	secerrors "github.com/Dorico-Dynamics/txova-go-security"
)

const (
	// PINLength is the standard length for ride PINs.
	PINLength = 4

	// MaxRetries is the maximum number of attempts to generate a valid PIN.
	MaxRetries = 10

	// MaxPINValue is the maximum value for a 4-digit PIN (exclusive).
	maxPINValue = 10000
)

// DefaultBlacklist contains PINs that are not allowed due to being too predictable.
// This includes all repeated digits, ascending sequences, and descending sequences.
var DefaultBlacklist = map[string]struct{}{
	// Repeated digits
	"0000": {},
	"1111": {},
	"2222": {},
	"3333": {},
	"4444": {},
	"5555": {},
	"6666": {},
	"7777": {},
	"8888": {},
	"9999": {},
	// Ascending sequences
	"0123": {},
	"1234": {},
	"2345": {},
	"3456": {},
	"4567": {},
	"5678": {},
	"6789": {},
	// Descending sequences
	"9876": {},
	"8765": {},
	"7654": {},
	"6543": {},
	"5432": {},
	"4321": {},
	"3210": {},
}

// Config holds the configuration for PIN generation.
type Config struct {
	Blacklist map[string]struct{}
}

// Option is a functional option for configuring PIN generation.
type Option func(*Config)

// WithBlacklist sets a custom blacklist of disallowed PINs.
func WithBlacklist(blacklist map[string]struct{}) Option {
	return func(c *Config) {
		c.Blacklist = blacklist
	}
}

// WithAdditionalBlacklist adds PINs to the default blacklist.
func WithAdditionalBlacklist(pins ...string) Option {
	return func(c *Config) {
		if c.Blacklist == nil {
			c.Blacklist = make(map[string]struct{})
		}
		for _, pin := range pins {
			c.Blacklist[pin] = struct{}{}
		}
	}
}

// Generator generates secure PINs.
type Generator struct {
	config Config
}

// NewGenerator creates a new PIN generator with the given options.
func NewGenerator(opts ...Option) *Generator {
	// Copy default blacklist
	blacklist := make(map[string]struct{}, len(DefaultBlacklist))
	for k, v := range DefaultBlacklist {
		blacklist[k] = v
	}

	config := Config{
		Blacklist: blacklist,
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &Generator{config: config}
}

// Generate creates a new cryptographically secure 4-digit PIN.
// It retries up to MaxRetries times if the generated PIN fails validation.
func (g *Generator) Generate() (string, error) {
	for range MaxRetries {
		pin, err := g.generateRandom()
		if err != nil {
			return "", err
		}

		if err := g.Validate(pin); err == nil {
			return pin, nil
		}
	}

	return "", errors.InternalErrorWrap(
		"PIN generation failed",
		fmt.Errorf("failed to generate valid PIN after %d attempts", MaxRetries),
	)
}

// generateRandom generates a random 4-digit PIN using crypto/rand.
func (g *Generator) generateRandom() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(maxPINValue))
	if err != nil {
		return "", errors.InternalErrorWrap("failed to generate random number", err)
	}

	return fmt.Sprintf("%04d", n.Int64()), nil
}

// Validate checks if a PIN meets all security requirements.
// Returns nil if valid, or an error describing the validation failure.
func (g *Generator) Validate(pin string) error {
	// Check length
	if len(pin) != PINLength {
		return secerrors.InvalidPIN(fmt.Sprintf("PIN must be exactly %d digits", PINLength))
	}

	// Check all characters are ASCII digits (0-9 only).
	for i := range len(pin) {
		if pin[i] < '0' || pin[i] > '9' {
			return secerrors.InvalidPIN("PIN must contain only digits")
		}
	}

	// Check blacklist
	if _, blacklisted := g.config.Blacklist[pin]; blacklisted {
		return secerrors.InvalidPIN("PIN is not allowed")
	}

	// Check for sequential ascending (e.g., 0123, 1234)
	if isSequentialAscending(pin) {
		return secerrors.InvalidPIN("PIN cannot be sequential ascending")
	}

	// Check for sequential descending (e.g., 9876, 8765)
	if isSequentialDescending(pin) {
		return secerrors.InvalidPIN("PIN cannot be sequential descending")
	}

	// Check for repeated digits (e.g., 0000, 1111)
	if isAllSameDigit(pin) {
		return secerrors.InvalidPIN("PIN cannot have all same digits")
	}

	return nil
}

// isSequentialAscending checks if the PIN is a sequence of ascending digits.
func isSequentialAscending(pin string) bool {
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[i-1]+1 {
			return false
		}
	}
	return true
}

// isSequentialDescending checks if the PIN is a sequence of descending digits.
func isSequentialDescending(pin string) bool {
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[i-1]-1 {
			return false
		}
	}
	return true
}

// isAllSameDigit checks if all digits in the PIN are the same.
func isAllSameDigit(pin string) bool {
	if pin == "" {
		return false
	}
	first := pin[0]
	for i := 1; i < len(pin); i++ {
		if pin[i] != first {
			return false
		}
	}
	return true
}

// Generate is a convenience function that uses the default generator.
func Generate() (string, error) {
	return NewGenerator().Generate()
}

// Validate is a convenience function that uses the default generator.
func Validate(pin string) error {
	return NewGenerator().Validate(pin)
}
