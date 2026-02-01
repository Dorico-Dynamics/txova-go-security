package token

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

func TestGenerate(t *testing.T) {
	token, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should be 64 hex characters (32 bytes)
	if len(token) != 64 {
		t.Errorf("Generate() length = %d, want 64", len(token))
	}

	// Should be valid hex
	_, err = hex.DecodeString(token)
	if err != nil {
		t.Errorf("Generate() produced invalid hex: %v", err)
	}
}

func TestGenerateUniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		token, err := Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if tokens[token] {
			t.Errorf("Generate() produced duplicate token at iteration %d", i)
		}
		tokens[token] = true
	}
}

func TestGenerateWithLength(t *testing.T) {
	tests := []struct {
		name    string
		bytes   int
		wantLen int
		wantErr bool
	}{
		{
			name:    "minimum length",
			bytes:   MinTokenBytes,
			wantLen: MinTokenBytes * 2, // hex encoding doubles length
			wantErr: false,
		},
		{
			name:    "standard 32 bytes",
			bytes:   32,
			wantLen: 64,
			wantErr: false,
		},
		{
			name:    "maximum length",
			bytes:   MaxTokenBytes,
			wantLen: MaxTokenBytes * 2,
			wantErr: false,
		},
		{
			name:    "too short",
			bytes:   MinTokenBytes - 1,
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "too long",
			bytes:   MaxTokenBytes + 1,
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateWithLength(tt.bytes)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateWithLength() expected error")
				}
				if !errors.IsValidationError(err) {
					t.Errorf("GenerateWithLength() should return validation error, got %T", err)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateWithLength() error = %v", err)
				return
			}

			if len(token) != tt.wantLen {
				t.Errorf("GenerateWithLength() length = %d, want %d", len(token), tt.wantLen)
			}
		})
	}
}

func TestGenerateURLSafe(t *testing.T) {
	token, err := GenerateURLSafe()
	if err != nil {
		t.Fatalf("GenerateURLSafe() error = %v", err)
	}

	// Check it doesn't contain URL-unsafe characters
	if strings.ContainsAny(token, "+/=") {
		t.Errorf("GenerateURLSafe() contains unsafe characters: %s", token)
	}

	// Should be valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("GenerateURLSafe() produced invalid base64: %v", err)
	}

	// Should decode to 32 bytes
	if len(decoded) != 32 {
		t.Errorf("GenerateURLSafe() decoded length = %d, want 32", len(decoded))
	}
}

func TestGenerateURLSafeWithLength(t *testing.T) {
	tests := []struct {
		name          string
		bytes         int
		wantDecodeLen int
		wantErr       bool
	}{
		{
			name:          "minimum length",
			bytes:         MinTokenBytes,
			wantDecodeLen: MinTokenBytes,
			wantErr:       false,
		},
		{
			name:          "standard 32 bytes",
			bytes:         32,
			wantDecodeLen: 32,
			wantErr:       false,
		},
		{
			name:          "too short",
			bytes:         MinTokenBytes - 1,
			wantDecodeLen: 0,
			wantErr:       true,
		},
		{
			name:          "too long",
			bytes:         MaxTokenBytes + 1,
			wantDecodeLen: 0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateURLSafeWithLength(tt.bytes)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateURLSafeWithLength() expected error")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateURLSafeWithLength() error = %v", err)
				return
			}

			decoded, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Fatalf("base64.RawURLEncoding.DecodeString() error = %v", err)
			}
			if len(decoded) != tt.wantDecodeLen {
				t.Errorf("GenerateURLSafeWithLength() decoded length = %d, want %d", len(decoded), tt.wantDecodeLen)
			}
		})
	}
}

func TestGenerateBytes(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantLen int
		wantErr bool
	}{
		{
			name:    "minimum length",
			length:  MinTokenBytes,
			wantLen: MinTokenBytes,
			wantErr: false,
		},
		{
			name:    "standard 32 bytes",
			length:  32,
			wantLen: 32,
			wantErr: false,
		},
		{
			name:    "too short",
			length:  MinTokenBytes - 1,
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "too long",
			length:  MaxTokenBytes + 1,
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, err := GenerateBytes(tt.length)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateBytes() expected error")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateBytes() error = %v", err)
				return
			}

			if len(bytes) != tt.wantLen {
				t.Errorf("GenerateBytes() length = %d, want %d", len(bytes), tt.wantLen)
			}
		})
	}
}

func TestTypeSpecificGenerators(t *testing.T) {
	tests := []struct {
		name      string
		generator func() (string, error)
		wantLen   int
	}{
		{"GenerateSessionToken", GenerateSessionToken, SessionTokenBytes * 2},
		{"GenerateRefreshToken", GenerateRefreshToken, RefreshTokenBytes * 2},
		{"GenerateAPIKey", GenerateAPIKey, APIKeyBytes * 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.generator()
			if err != nil {
				t.Errorf("%s() error = %v", tt.name, err)
				return
			}
			if len(token) != tt.wantLen {
				t.Errorf("%s() length = %d, want %d", tt.name, len(token), tt.wantLen)
			}
		})
	}
}

func TestURLSafeTypeSpecificGenerators(t *testing.T) {
	tests := []struct {
		name      string
		generator func() (string, error)
		wantBytes int
	}{
		{"GenerateResetToken", GenerateResetToken, ResetTokenBytes},
		{"GenerateVerificationToken", GenerateVerificationToken, VerificationTokenBytes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.generator()
			if err != nil {
				t.Errorf("%s() error = %v", tt.name, err)
				return
			}

			// Should be valid URL-safe base64
			decoded, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Errorf("%s() produced invalid base64: %v", tt.name, err)
				return
			}
			if len(decoded) != tt.wantBytes {
				t.Errorf("%s() decoded length = %d, want %d", tt.name, len(decoded), tt.wantBytes)
			}
		})
	}
}

func TestHash(t *testing.T) {
	token := "test-token-12345"
	hash := Hash(token)

	// SHA-256 produces 32 bytes = 64 hex characters
	if len(hash) != 64 {
		t.Errorf("Hash() length = %d, want 64", len(hash))
	}

	// Should be valid hex
	_, err := hex.DecodeString(hash)
	if err != nil {
		t.Errorf("Hash() produced invalid hex: %v", err)
	}

	// Same token should produce same hash
	hash2 := Hash(token)
	if hash != hash2 {
		t.Error("Hash() not deterministic")
	}

	// Different token should produce different hash
	hash3 := Hash("different-token")
	if hash == hash3 {
		t.Error("Hash() collision detected")
	}
}

func TestHashBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	hash := HashBytes(data)

	if len(hash) != 64 {
		t.Errorf("HashBytes() length = %d, want 64", len(hash))
	}

	// Same data should produce same hash
	hash2 := HashBytes(data)
	if hash != hash2 {
		t.Error("HashBytes() not deterministic")
	}
}

func TestCompare(t *testing.T) {
	token := "my-secret-token"
	hashedToken := Hash(token)

	tests := []struct {
		name  string
		token string
		hash  string
		want  bool
	}{
		{
			name:  "correct token",
			token: token,
			hash:  hashedToken,
			want:  true,
		},
		{
			name:  "wrong token",
			token: "wrong-token",
			hash:  hashedToken,
			want:  false,
		},
		{
			name:  "empty token",
			token: "",
			hash:  hashedToken,
			want:  false,
		},
		{
			name:  "case sensitive",
			token: "MY-SECRET-TOKEN",
			hash:  hashedToken,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.token, tt.hash); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompareBytes(t *testing.T) {
	data := []byte("my-secret-data")
	hashedData := HashBytes(data)

	tests := []struct {
		name string
		data []byte
		hash string
		want bool
	}{
		{
			name: "correct data",
			data: data,
			hash: hashedData,
			want: true,
		},
		{
			name: "wrong data",
			data: []byte("wrong-data"),
			hash: hashedData,
			want: false,
		},
		{
			name: "empty data",
			data: []byte{},
			hash: hashedData,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareBytes(tt.data, tt.hash); got != tt.want {
				t.Errorf("CompareBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidHexToken(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		expectedBytes int
		want          bool
	}{
		{
			name:          "valid 32-byte hex",
			token:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expectedBytes: 32,
			want:          true,
		},
		{
			name:          "valid 16-byte hex",
			token:         "0123456789abcdef0123456789abcdef",
			expectedBytes: 16,
			want:          true,
		},
		{
			name:          "wrong length",
			token:         "0123456789abcdef",
			expectedBytes: 32,
			want:          false,
		},
		{
			name:          "invalid hex characters",
			token:         "ghijklmnopqrstuv0123456789abcdef",
			expectedBytes: 16,
			want:          false,
		},
		{
			name:          "empty",
			token:         "",
			expectedBytes: 32,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidHexToken(tt.token, tt.expectedBytes); got != tt.want {
				t.Errorf("IsValidHexToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidBase64Token(t *testing.T) {
	// Generate a valid token for testing
	validToken, _ := GenerateURLSafe()

	tests := []struct {
		name          string
		token         string
		expectedBytes int
		want          bool
	}{
		{
			name:          "valid 32-byte base64",
			token:         validToken,
			expectedBytes: 32,
			want:          true,
		},
		{
			name:          "wrong decoded length",
			token:         validToken,
			expectedBytes: 16,
			want:          false,
		},
		{
			name:          "invalid base64",
			token:         "!!!invalid!!!",
			expectedBytes: 32,
			want:          false,
		},
		{
			name:          "empty",
			token:         "",
			expectedBytes: 32,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidBase64Token(tt.token, tt.expectedBytes); got != tt.want {
				t.Errorf("IsValidBase64Token() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Generate()
	}
}

func BenchmarkGenerateURLSafe(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateURLSafe()
	}
}

func BenchmarkHash(b *testing.B) {
	token := "benchmark-token-for-hashing"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Hash(token)
	}
}

func BenchmarkCompare(b *testing.B) {
	token := "benchmark-token-for-comparison"
	hashedToken := Hash(token)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compare(token, hashedToken)
	}
}
