package mask

import (
	"testing"

	"github.com/Dorico-Dynamics/txova-go-types/contact"
)

func TestPhone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "mozambique format", input: "+258841234567", expected: "+2588****4567"},
		{name: "with spaces", input: "+258 84 123 4567", expected: "+2588****4567"},
		{name: "with dashes", input: "+258-84-123-4567", expected: "+2588****4567"},
		{name: "us format", input: "+1 555 123 4567", expected: "+1555***4567"},
		{name: "no country code", input: "841234567", expected: "*****4567"},
		{name: "short number 4 digits", input: "1234", expected: "1234"},
		{name: "very short", input: "123", expected: "***"},
		{name: "with parentheses", input: "+1 (555) 123-4567", expected: "+1555***4567"},
		{name: "local format", input: "0841234567", expected: "******4567"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Phone(tt.input)
			if result != tt.expected {
				t.Errorf("Phone(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPhoneNumber(t *testing.T) {
	// Test with contact.PhoneNumber type
	phone, err := contact.ParsePhoneNumber("+258841234567")
	if err != nil {
		t.Skipf("contact.ParsePhoneNumber failed: %v", err)
	}

	result := PhoneNumber(phone)
	// The exact format depends on PhoneNumber.String() implementation
	if result == "" {
		t.Error("expected non-empty masked phone")
	}
}

func TestEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "standard email", input: "user@example.com", expected: "u***@example.com"},
		{name: "long local part", input: "username@domain.org", expected: "u*******@domain.org"},
		{name: "single char local", input: "u@test.com", expected: "u***@test.com"},
		{name: "two char local", input: "ab@test.com", expected: "a***@test.com"},
		{name: "no at sign", input: "notanemail", expected: "**********"},
		{name: "empty local part", input: "@domain.com", expected: "***@domain.com"},
		{name: "subdomain", input: "user@mail.example.com", expected: "u***@mail.example.com"},
		{name: "plus addressing", input: "user+tag@example.com", expected: "u*******@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Email(tt.input)
			if result != tt.expected {
				t.Errorf("Email(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEmailAddress(t *testing.T) {
	// Test with contact.Email type
	email, err := contact.ParseEmail("test@example.com")
	if err != nil {
		t.Skipf("contact.ParseEmail failed: %v", err)
	}

	result := EmailAddress(email)
	if result == "" {
		t.Error("expected non-empty masked email")
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "single name", input: "John", expected: "J***"},
		{name: "two names", input: "John Smith", expected: "J*** S****"},
		{name: "three names", input: "John Smith Jr", expected: "J*** S**** J*"},
		{name: "single letter", input: "J", expected: "J"},
		{name: "two letters", input: "Jo", expected: "J*"},
		{name: "multiple spaces", input: "John   Smith", expected: "J*** S****"},
		{name: "unicode name", input: "José María", expected: "J*** M****"},
		{name: "whitespace only", input: "   ", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Name(tt.input)
			if result != tt.expected {
				t.Errorf("Name(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "standard 16 digits", input: "4111111111111111", expected: "************1111"},
		{name: "with spaces", input: "4111 1111 1111 1111", expected: "************1111"},
		{name: "with dashes", input: "4111-1111-1111-1111", expected: "************1111"},
		{name: "amex 15 digits", input: "378282246310005", expected: "***********0005"},
		{name: "short number", input: "1234", expected: "****"},
		{name: "very short", input: "123", expected: "***"},
		{name: "non-digits only", input: "abcd", expected: ""},
		{name: "mixed", input: "4111-abcd-1111-1111", expected: "********1111"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Card(tt.input)
			if result != tt.expected {
				t.Errorf("Card(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "standard passport", input: "AB1234567", expected: "AB****567"},
		{name: "national ID", input: "123456789012", expected: "12*******012"},
		{name: "short ID 5 chars", input: "AB123", expected: "A***3"},
		{name: "very short 3 chars", input: "AB1", expected: "A*1"},
		{name: "two chars", input: "AB", expected: "**"},
		{name: "one char", input: "A", expected: "*"},
		{name: "six chars", input: "AB1234", expected: "AB*234"},
		{name: "unicode chars", input: "ÄB12345", expected: "ÄB**345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ID(tt.input)
			if result != tt.expected {
				t.Errorf("ID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMasker_CustomMaskChar(t *testing.T) {
	masker := NewMasker(WithMaskChar('#'))

	t.Run("phone with custom char", func(t *testing.T) {
		result := masker.Phone("+258841234567")
		if result != "+2588####4567" {
			t.Errorf("expected +2588####4567, got %q", result)
		}
	})

	t.Run("email with custom char", func(t *testing.T) {
		result := masker.Email("user@example.com")
		if result != "u###@example.com" {
			t.Errorf("expected u###@example.com, got %q", result)
		}
	})

	t.Run("name with custom char", func(t *testing.T) {
		result := masker.Name("John Smith")
		if result != "J### S####" {
			t.Errorf("expected J### S####, got %q", result)
		}
	})

	t.Run("card with custom char", func(t *testing.T) {
		result := masker.Card("4111111111111111")
		if result != "############1111" {
			t.Errorf("expected ############1111, got %q", result)
		}
	})

	t.Run("ID with custom char", func(t *testing.T) {
		result := masker.ID("AB1234567")
		if result != "AB####567" {
			t.Errorf("expected AB####567, got %q", result)
		}
	})
}

func TestNewMasker_Default(t *testing.T) {
	masker := NewMasker()
	if masker.maskChar != DefaultMaskChar {
		t.Errorf("expected default mask char %q, got %q", DefaultMaskChar, masker.maskChar)
	}
}

func TestCleanPhone(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"+258 84 123 4567", "+258841234567"},
		{"+1 (555) 123-4567", "+15551234567"},
		{"84-123-4567", "841234567"},
		{"", ""},
		{"abc", ""},
	}

	for _, tt := range tests {
		result := cleanPhone(tt.input)
		if result != tt.expected {
			t.Errorf("cleanPhone(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractDigits(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"4111-1111-1111-1111", "4111111111111111"},
		{"abc123def", "123"},
		{"", ""},
		{"no digits", ""},
	}

	for _, tt := range tests {
		result := extractDigits(tt.input)
		if result != tt.expected {
			t.Errorf("extractDigits(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestRepeatRune(t *testing.T) {
	tests := []struct {
		r        rune
		n        int
		expected string
	}{
		{'*', 5, "*****"},
		{'#', 3, "###"},
		{'*', 0, ""},
		{'*', -1, ""},
	}

	for _, tt := range tests {
		result := string(repeatRune(tt.r, tt.n))
		if result != tt.expected {
			t.Errorf("repeatRune(%q, %d) = %q, want %q", tt.r, tt.n, result, tt.expected)
		}
	}
}

func BenchmarkPhone(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Phone("+258841234567")
	}
}

func BenchmarkEmail(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Email("user@example.com")
	}
}

func BenchmarkName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Name("John Smith")
	}
}

func BenchmarkCard(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Card("4111111111111111")
	}
}

func BenchmarkID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ID("AB1234567")
	}
}
