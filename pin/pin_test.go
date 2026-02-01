package pin

import (
	"testing"

	secerrors "github.com/Dorico-Dynamics/txova-go-security"
)

func TestGenerate(t *testing.T) {
	t.Run("generates valid 4-digit PIN", func(t *testing.T) {
		pin, err := Generate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(pin) != PINLength {
			t.Errorf("expected PIN length %d, got %d", PINLength, len(pin))
		}

		// Verify it's all digits
		for _, c := range pin {
			if c < '0' || c > '9' {
				t.Errorf("PIN contains non-digit character: %c", c)
			}
		}
	})

	t.Run("generated PINs pass validation", func(t *testing.T) {
		generator := NewGenerator()

		for i := 0; i < 10000; i++ {
			pin, err := generator.Generate()
			if err != nil {
				t.Fatalf("generation failed: %v", err)
			}

			if err := generator.Validate(pin); err != nil {
				t.Errorf("generated PIN %s failed validation: %v", pin, err)
			}
		}
	})

	t.Run("generates unique PINs", func(t *testing.T) {
		seen := make(map[string]int)
		generator := NewGenerator()

		// Generate many PINs and check distribution
		// With 10000 - ~24 blacklisted PINs = ~9976 valid PINs
		// Generating 1000 should show some duplicates but good distribution
		for i := 0; i < 1000; i++ {
			pin, err := generator.Generate()
			if err != nil {
				t.Fatalf("generation failed: %v", err)
			}
			seen[pin]++
		}

		// Should have generated many different PINs
		if len(seen) < 500 {
			t.Errorf("expected at least 500 unique PINs, got %d", len(seen))
		}
	})
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		pin     string
		wantErr bool
		errMsg  string
	}{
		// Valid PINs
		{name: "valid PIN 5839", pin: "5839", wantErr: false},
		{name: "valid PIN 0001", pin: "0001", wantErr: false},
		{name: "valid PIN 9998", pin: "9998", wantErr: false},
		{name: "valid PIN 1357", pin: "1357", wantErr: false},
		{name: "valid PIN 2468", pin: "2468", wantErr: false},

		// Invalid length
		{name: "empty PIN", pin: "", wantErr: true, errMsg: "must be exactly 4 digits"},
		{name: "too short", pin: "123", wantErr: true, errMsg: "must be exactly 4 digits"},
		{name: "too long", pin: "12345", wantErr: true, errMsg: "must be exactly 4 digits"},

		// Non-digit characters
		{name: "contains letter", pin: "123a", wantErr: true, errMsg: "must contain only digits"},
		{name: "contains special char", pin: "12#4", wantErr: true, errMsg: "must contain only digits"},
		{name: "contains space", pin: "12 4", wantErr: true, errMsg: "must contain only digits"},

		// Blacklisted - repeated digits
		{name: "repeated 0000", pin: "0000", wantErr: true},
		{name: "repeated 1111", pin: "1111", wantErr: true},
		{name: "repeated 2222", pin: "2222", wantErr: true},
		{name: "repeated 3333", pin: "3333", wantErr: true},
		{name: "repeated 4444", pin: "4444", wantErr: true},
		{name: "repeated 5555", pin: "5555", wantErr: true},
		{name: "repeated 6666", pin: "6666", wantErr: true},
		{name: "repeated 7777", pin: "7777", wantErr: true},
		{name: "repeated 8888", pin: "8888", wantErr: true},
		{name: "repeated 9999", pin: "9999", wantErr: true},

		// Blacklisted - ascending sequences
		{name: "ascending 0123", pin: "0123", wantErr: true},
		{name: "ascending 1234", pin: "1234", wantErr: true},
		{name: "ascending 2345", pin: "2345", wantErr: true},
		{name: "ascending 3456", pin: "3456", wantErr: true},
		{name: "ascending 4567", pin: "4567", wantErr: true},
		{name: "ascending 5678", pin: "5678", wantErr: true},
		{name: "ascending 6789", pin: "6789", wantErr: true},

		// Blacklisted - descending sequences
		{name: "descending 9876", pin: "9876", wantErr: true},
		{name: "descending 8765", pin: "8765", wantErr: true},
		{name: "descending 7654", pin: "7654", wantErr: true},
		{name: "descending 6543", pin: "6543", wantErr: true},
		{name: "descending 5432", pin: "5432", wantErr: true},
		{name: "descending 4321", pin: "4321", wantErr: true},
		{name: "descending 3210", pin: "3210", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.pin)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for PIN %q, got nil", tt.pin)
					return
				}

				// Verify it's the correct error type
				if !secerrors.IsInvalidPIN(err) {
					t.Errorf("expected InvalidPIN error, got: %v", err)
				}

				// Check error message if specified
				if tt.errMsg != "" {
					if errStr := err.Error(); !contains(errStr, tt.errMsg) {
						t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error for PIN %q: %v", tt.pin, err)
			}
		})
	}
}

func TestValidate_SequentialDetection(t *testing.T) {
	generator := NewGenerator()

	// Test that sequential detection works even for PINs not in blacklist
	tests := []struct {
		pin        string
		ascending  bool
		descending bool
	}{
		{"0123", true, false},
		{"1234", true, false},
		{"6789", true, false},
		{"9876", false, true},
		{"4321", false, true},
		{"3210", false, true},
		{"1357", false, false}, // not sequential
		{"2468", false, false}, // not sequential
		{"1122", false, false}, // not sequential
		{"5839", false, false}, // not sequential
	}

	for _, tt := range tests {
		t.Run(tt.pin, func(t *testing.T) {
			if got := isSequentialAscending(tt.pin); got != tt.ascending {
				t.Errorf("isSequentialAscending(%q) = %v, want %v", tt.pin, got, tt.ascending)
			}
			if got := isSequentialDescending(tt.pin); got != tt.descending {
				t.Errorf("isSequentialDescending(%q) = %v, want %v", tt.pin, got, tt.descending)
			}

			// Verify validation rejects sequential PINs
			err := generator.Validate(tt.pin)
			if (tt.ascending || tt.descending) && err == nil {
				t.Errorf("expected error for sequential PIN %q", tt.pin)
			}
		})
	}
}

func TestValidate_RepeatedDigitDetection(t *testing.T) {
	tests := []struct {
		pin      string
		repeated bool
	}{
		{"0000", true},
		{"1111", true},
		{"9999", true},
		{"0001", false},
		{"1110", false},
		{"1122", false},
		{"5839", false},
	}

	for _, tt := range tests {
		t.Run(tt.pin, func(t *testing.T) {
			if got := isAllSameDigit(tt.pin); got != tt.repeated {
				t.Errorf("isAllSameDigit(%q) = %v, want %v", tt.pin, got, tt.repeated)
			}
		})
	}
}

func TestNewGenerator_WithOptions(t *testing.T) {
	t.Run("custom blacklist", func(t *testing.T) {
		customBlacklist := map[string]struct{}{
			"1357": {},
			"2468": {},
		}

		generator := NewGenerator(WithBlacklist(customBlacklist))

		// Custom blacklisted PINs should fail
		if err := generator.Validate("1357"); err == nil {
			t.Error("expected error for custom blacklisted PIN 1357")
		}
		if err := generator.Validate("2468"); err == nil {
			t.Error("expected error for custom blacklisted PIN 2468")
		}

		// Default blacklisted PINs should still fail (due to sequential/repeated checks)
		if err := generator.Validate("1234"); err == nil {
			t.Error("expected error for sequential PIN 1234")
		}
		if err := generator.Validate("1111"); err == nil {
			t.Error("expected error for repeated PIN 1111")
		}
	})

	t.Run("additional blacklist", func(t *testing.T) {
		generator := NewGenerator(WithAdditionalBlacklist("1357", "2468", "1379"))

		// Additional blacklisted PINs should fail
		if err := generator.Validate("1357"); err == nil {
			t.Error("expected error for additional blacklisted PIN 1357")
		}
		if err := generator.Validate("2468"); err == nil {
			t.Error("expected error for additional blacklisted PIN 2468")
		}
		if err := generator.Validate("1379"); err == nil {
			t.Error("expected error for additional blacklisted PIN 1379")
		}

		// Default blacklisted PINs should still fail
		if err := generator.Validate("1234"); err == nil {
			t.Error("expected error for default blacklisted PIN 1234")
		}
	})
}

func TestGenerator_generateRandom(t *testing.T) {
	generator := NewGenerator()

	// Generate many PINs and verify format
	for i := 0; i < 1000; i++ {
		pin, err := generator.generateRandom()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(pin) != 4 {
			t.Errorf("expected length 4, got %d for PIN %q", len(pin), pin)
		}

		// Should be zero-padded
		for _, c := range pin {
			if c < '0' || c > '9' {
				t.Errorf("non-digit character in PIN: %c", c)
			}
		}
	}
}

func TestDefaultBlacklist(t *testing.T) {
	// Verify all expected entries are in the default blacklist
	expectedBlacklisted := []string{
		// Repeated
		"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
		// Ascending
		"0123", "1234", "2345", "3456", "4567", "5678", "6789",
		// Descending
		"9876", "8765", "7654", "6543", "5432", "4321", "3210",
	}

	for _, pin := range expectedBlacklisted {
		if _, ok := DefaultBlacklist[pin]; !ok {
			t.Errorf("expected PIN %q to be in default blacklist", pin)
		}
	}

	// Verify count matches
	if len(DefaultBlacklist) != len(expectedBlacklisted) {
		t.Errorf("expected %d entries in blacklist, got %d", len(expectedBlacklisted), len(DefaultBlacklist))
	}
}

func TestIsAllSameDigit_EmptyString(t *testing.T) {
	if isAllSameDigit("") {
		t.Error("empty string should not be considered all same digit")
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func BenchmarkGenerate(b *testing.B) {
	generator := NewGenerator()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.Generate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	generator := NewGenerator()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = generator.Validate("5839")
	}
}
