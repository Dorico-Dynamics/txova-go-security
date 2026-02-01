// Package mask provides PII (Personally Identifiable Information) masking utilities.
// These functions help safely log or display sensitive data by obscuring parts of it.
package mask

import (
	"strings"
	"unicode"

	"github.com/Dorico-Dynamics/txova-go-types/contact"
)

const (
	// DefaultMaskChar is the default character used for masking.
	DefaultMaskChar = '*'
)

// Masker provides PII masking with configurable options.
type Masker struct {
	maskChar rune
}

// Option is a functional option for configuring the Masker.
type Option func(*Masker)

// WithMaskChar sets a custom mask character.
func WithMaskChar(char rune) Option {
	return func(m *Masker) {
		m.maskChar = char
	}
}

// NewMasker creates a new Masker with the given options.
func NewMasker(opts ...Option) *Masker {
	m := &Masker{
		maskChar: DefaultMaskChar,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Phone masks a phone number, preserving country code prefix and last 4 digits.
// Format: +258****4567.
func (m *Masker) Phone(phone string) string {
	if phone == "" {
		return ""
	}

	// Remove any spaces, dashes, or parentheses for processing
	cleaned := cleanPhone(phone)
	if cleaned == "" {
		return ""
	}

	// Handle various formats
	var prefix string
	var digits string

	if cleaned[0] == '+' {
		// Find where the country code ends (assume up to 3 digits after +)
		idx := 1
		for idx < len(cleaned) && idx <= 4 && cleaned[idx] >= '0' && cleaned[idx] <= '9' {
			idx++
		}
		prefix = cleaned[:idx]
		digits = cleaned[idx:]
	} else {
		digits = cleaned
	}

	// Need at least 4 digits to mask meaningfully
	if len(digits) < 4 {
		return string(repeatRune(m.maskChar, len(cleaned)))
	}

	// Mask all but last 4 digits
	maskedLen := len(digits) - 4
	lastFour := digits[len(digits)-4:]

	return prefix + string(repeatRune(m.maskChar, maskedLen)) + lastFour
}

// PhoneNumber masks a contact.PhoneNumber.
func (m *Masker) PhoneNumber(phone contact.PhoneNumber) string {
	return m.Phone(phone.String())
}

// Email masks an email address, preserving first char of local part and full domain.
// Format: u***@example.com.
func (m *Masker) Email(email string) string {
	if email == "" {
		return ""
	}

	atIdx := strings.LastIndex(email, "@")
	if atIdx == -1 {
		// Not a valid email format, mask entirely
		return string(repeatRune(m.maskChar, len(email)))
	}

	localPart := email[:atIdx]
	domain := email[atIdx:]

	if localPart == "" {
		return string(repeatRune(m.maskChar, 3)) + domain
	}

	// Preserve first character, mask the rest
	firstChar := string(localPart[0])
	maskedLen := len(localPart) - 1
	if maskedLen < 3 {
		maskedLen = 3 // Minimum mask length for privacy
	}

	return firstChar + string(repeatRune(m.maskChar, maskedLen)) + domain
}

// EmailAddress masks a contact.Email.
func (m *Masker) EmailAddress(email contact.Email) string {
	return m.Email(email.String())
}

// Name masks a name, preserving first character of each word.
// Format: J*** S****.
func (m *Masker) Name(name string) string {
	if name == "" {
		return ""
	}

	words := strings.Fields(name)
	if len(words) == 0 {
		return ""
	}

	masked := make([]string, len(words))
	for i, word := range words {
		if word == "" {
			continue
		}

		runes := []rune(word)
		firstChar := string(runes[0])
		remainingLen := len(runes) - 1

		if remainingLen <= 0 {
			masked[i] = firstChar
		} else {
			masked[i] = firstChar + string(repeatRune(m.maskChar, remainingLen))
		}
	}

	return strings.Join(masked, " ")
}

// Card masks a card number, preserving only last 4 digits.
// Format: ****1111.
func (m *Masker) Card(number string) string {
	if number == "" {
		return ""
	}

	// Extract only digits
	digits := extractDigits(number)
	if digits == "" {
		return ""
	}

	if len(digits) <= 4 {
		return string(repeatRune(m.maskChar, len(digits)))
	}

	lastFour := digits[len(digits)-4:]
	maskedLen := len(digits) - 4

	return string(repeatRune(m.maskChar, maskedLen)) + lastFour
}

// ID masks an ID document number, preserving first 2 chars and last 3 chars.
// Format: AB***456.
func (m *Masker) ID(id string) string {
	if id == "" {
		return ""
	}

	runes := []rune(id)
	length := len(runes)

	// For very short IDs, mask the middle
	if length <= 5 {
		if length <= 2 {
			return string(repeatRune(m.maskChar, length))
		}
		// Keep first and last, mask middle
		return string(runes[0]) + string(repeatRune(m.maskChar, length-2)) + string(runes[length-1])
	}

	// Standard format: first 2 + mask + last 3
	first := string(runes[:2])
	last := string(runes[length-3:])
	maskedLen := length - 5

	return first + string(repeatRune(m.maskChar, maskedLen)) + last
}

// Helper functions

// cleanPhone removes common phone formatting characters.
func cleanPhone(phone string) string {
	var sb strings.Builder
	sb.Grow(len(phone))

	for _, r := range phone {
		if r == '+' || unicode.IsDigit(r) {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

// extractDigits extracts only digit characters from a string.
func extractDigits(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))

	for _, r := range s {
		if unicode.IsDigit(r) {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

// repeatRune creates a string of n repeated runes.
func repeatRune(r rune, n int) []rune {
	if n <= 0 {
		return nil
	}
	result := make([]rune, n)
	for i := range result {
		result[i] = r
	}
	return result
}

// Package-level convenience functions using default masker.

var defaultMasker = NewMasker()

// Phone masks a phone number using the default masker.
func Phone(phone string) string {
	return defaultMasker.Phone(phone)
}

// PhoneNumber masks a contact.PhoneNumber using the default masker.
func PhoneNumber(phone contact.PhoneNumber) string {
	return defaultMasker.PhoneNumber(phone)
}

// Email masks an email address using the default masker.
func Email(email string) string {
	return defaultMasker.Email(email)
}

// EmailAddress masks a contact.Email using the default masker.
func EmailAddress(email contact.Email) string {
	return defaultMasker.EmailAddress(email)
}

// Name masks a name using the default masker.
func Name(name string) string {
	return defaultMasker.Name(name)
}

// Card masks a card number using the default masker.
func Card(number string) string {
	return defaultMasker.Card(number)
}

// ID masks an ID document using the default masker.
func ID(id string) string {
	return defaultMasker.ID(id)
}
