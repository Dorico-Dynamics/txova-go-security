package password

import (
	"context"
	"strings"
	"testing"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

func TestHasher_Hash(t *testing.T) {
	ctx := context.Background()
	h := NewDefault()

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "valid password",
			password: "securePassword123!",
			wantErr:  nil,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  ErrEmptyPassword,
		},
		{
			name:     "unicode password",
			password: "密码安全测试123",
			wantErr:  nil,
		},
		{
			name:     "long password",
			password: strings.Repeat("a", 100),
			wantErr:  nil,
		},
		{
			name:     "password with special chars",
			password: "p@$$w0rd!#%&*()[]{}",
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := h.Hash(ctx, tt.password)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("Hash() unexpected error = %v", err)
				return
			}

			// Verify hash format (PHC string)
			if !strings.HasPrefix(hash, "$argon2id$v=") {
				t.Errorf("Hash() = %v, want PHC format starting with $argon2id$v=", hash)
			}

			// Verify hash contains expected parameters
			if !strings.Contains(hash, "m=65536,t=3,p=4") {
				t.Errorf("Hash() = %v, expected default parameters m=65536,t=3,p=4", hash)
			}

			// Verify hash parts count
			parts := strings.Split(hash, "$")
			if len(parts) != 6 {
				t.Errorf("Hash() produced %d parts, want 6", len(parts))
			}
		})
	}
}

func TestHasher_HashUniqueness(t *testing.T) {
	ctx := context.Background()
	h := NewDefault()
	password := "testPassword123!"

	// Generate multiple hashes for the same password
	hashes := make(map[string]bool)
	for i := 0; i < 10; i++ {
		hash, err := h.Hash(ctx, password)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}
		if hashes[hash] {
			t.Error("Hash() produced duplicate hash - salt not unique")
		}
		hashes[hash] = true
	}
}

func TestHasher_Verify(t *testing.T) {
	ctx := context.Background()
	h := NewDefault()

	password := "testPassword123!"
	hash, err := h.Hash(ctx, password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  error
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
			wantErr:  nil,
		},
		{
			name:     "incorrect password",
			password: "wrongPassword",
			hash:     hash,
			want:     false,
			wantErr:  nil,
		},
		{
			name:     "empty password",
			password: "",
			hash:     hash,
			want:     false,
			wantErr:  ErrEmptyPassword,
		},
		{
			name:     "empty hash",
			password: password,
			hash:     "",
			want:     false,
			wantErr:  ErrInvalidHash,
		},
		{
			name:     "invalid hash format",
			password: password,
			hash:     "invalid-hash",
			want:     false,
			wantErr:  ErrInvalidHash,
		},
		{
			name:     "case sensitive password",
			password: "TestPassword123!",
			hash:     hash,
			want:     false,
			wantErr:  nil,
		},
		{
			name:     "wrong algorithm",
			password: password,
			hash:     "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
			want:     false,
			wantErr:  ErrInvalidHash,
		},
		{
			name:     "malformed parameters",
			password: password,
			hash:     "$argon2id$v=19$invalid$c2FsdA$aGFzaA",
			want:     false,
			wantErr:  ErrInvalidHash,
		},
		{
			name:     "invalid base64 salt",
			password: password,
			hash:     "$argon2id$v=19$m=65536,t=3,p=4$!!!invalid!!!$aGFzaA",
			want:     false,
			wantErr:  ErrInvalidHash,
		},
		{
			name:     "invalid base64 hash",
			password: password,
			hash:     "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!invalid!!!",
			want:     false,
			wantErr:  ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.Verify(ctx, tt.password, tt.hash)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("Verify() unexpected error = %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher_VerifyWithDifferentParams(t *testing.T) {
	ctx := context.Background()

	// Hash with custom parameters
	customHasher := New(Config{
		Memory:      32 * 1024, // 32 MB
		Iterations:  2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	})

	password := "testPassword123!"
	hash, err := customHasher.Hash(ctx, password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Verify with default hasher (should still work as params are in hash)
	defaultHasher := NewDefault()
	valid, err := defaultHasher.Verify(ctx, password, hash)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
	if !valid {
		t.Error("Verify() should succeed with different hasher config")
	}
}

func TestHasher_NeedsRehash(t *testing.T) {
	ctx := context.Background()

	// Create hash with default config
	defaultHasher := NewDefault()
	hash, _ := defaultHasher.Hash(ctx, "password123")

	// Create hasher with different config
	customHasher := New(Config{
		Memory:      128 * 1024, // Different memory
		Iterations:  4,          // Different iterations
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	})

	tests := []struct {
		name    string
		hasher  *Hasher
		hash    string
		want    bool
		wantErr error
	}{
		{
			name:    "same config - no rehash",
			hasher:  defaultHasher,
			hash:    hash,
			want:    false,
			wantErr: nil,
		},
		{
			name:    "different config - needs rehash",
			hasher:  customHasher,
			hash:    hash,
			want:    true,
			wantErr: nil,
		},
		{
			name:    "empty hash",
			hasher:  defaultHasher,
			hash:    "",
			want:    false,
			wantErr: ErrInvalidHash,
		},
		{
			name:    "invalid hash",
			hasher:  defaultHasher,
			hash:    "not-a-hash",
			want:    false,
			wantErr: ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.hasher.NeedsRehash(tt.hash)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("NeedsRehash() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("NeedsRehash() unexpected error = %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("NeedsRehash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewWithOptions(t *testing.T) {
	h := NewWithOptions(
		WithMemory(128*1024),
		WithIterations(5),
		WithParallelism(2),
		WithSaltLength(32),
		WithKeyLength(64),
	)

	cfg := h.Config()

	if cfg.Memory != 128*1024 {
		t.Errorf("Memory = %d, want %d", cfg.Memory, 128*1024)
	}
	if cfg.Iterations != 5 {
		t.Errorf("Iterations = %d, want %d", cfg.Iterations, 5)
	}
	if cfg.Parallelism != 2 {
		t.Errorf("Parallelism = %d, want %d", cfg.Parallelism, 2)
	}
	if cfg.SaltLength != 32 {
		t.Errorf("SaltLength = %d, want %d", cfg.SaltLength, 32)
	}
	if cfg.KeyLength != 64 {
		t.Errorf("KeyLength = %d, want %d", cfg.KeyLength, 64)
	}
}

func TestNew_ZeroValues(t *testing.T) {
	// Test that zero values get replaced with defaults
	h := New(Config{})

	cfg := h.Config()

	if cfg.Memory != DefaultMemory {
		t.Errorf("Memory = %d, want %d", cfg.Memory, DefaultMemory)
	}
	if cfg.Iterations != DefaultIterations {
		t.Errorf("Iterations = %d, want %d", cfg.Iterations, DefaultIterations)
	}
	if cfg.Parallelism != DefaultParallelism {
		t.Errorf("Parallelism = %d, want %d", cfg.Parallelism, DefaultParallelism)
	}
	if cfg.SaltLength != DefaultSaltLength {
		t.Errorf("SaltLength = %d, want %d", cfg.SaltLength, DefaultSaltLength)
	}
	if cfg.KeyLength != DefaultKeyLength {
		t.Errorf("KeyLength = %d, want %d", cfg.KeyLength, DefaultKeyLength)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Memory != DefaultMemory {
		t.Errorf("Memory = %d, want %d", cfg.Memory, DefaultMemory)
	}
	if cfg.Iterations != DefaultIterations {
		t.Errorf("Iterations = %d, want %d", cfg.Iterations, DefaultIterations)
	}
	if cfg.Parallelism != DefaultParallelism {
		t.Errorf("Parallelism = %d, want %d", cfg.Parallelism, DefaultParallelism)
	}
	if cfg.SaltLength != DefaultSaltLength {
		t.Errorf("SaltLength = %d, want %d", cfg.SaltLength, DefaultSaltLength)
	}
	if cfg.KeyLength != DefaultKeyLength {
		t.Errorf("KeyLength = %d, want %d", cfg.KeyLength, DefaultKeyLength)
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "securePass123!",
			wantErr:  false,
		},
		{
			name:     "minimum length exactly",
			password: "12345678",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "1234567",
			wantErr:  true,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
		},
		{
			name:     "maximum length exactly",
			password: strings.Repeat("a", MaxPasswordLength),
			wantErr:  false,
		},
		{
			name:     "too long",
			password: strings.Repeat("a", MaxPasswordLength+1),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Verify it's a validation error
			if err != nil && !errors.IsValidationError(err) {
				t.Errorf("ValidatePassword() should return validation error, got %T", err)
			}
		})
	}
}

func TestParseConfigFromHash(t *testing.T) {
	ctx := context.Background()
	h := New(Config{
		Memory:      32 * 1024,
		Iterations:  2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	})

	hash, _ := h.Hash(ctx, "password")

	cfg, err := ParseConfigFromHash(hash)
	if err != nil {
		t.Fatalf("ParseConfigFromHash() error = %v", err)
	}

	if cfg.Memory != 32*1024 {
		t.Errorf("Memory = %d, want %d", cfg.Memory, 32*1024)
	}
	if cfg.Iterations != 2 {
		t.Errorf("Iterations = %d, want %d", cfg.Iterations, 2)
	}
	if cfg.Parallelism != 2 {
		t.Errorf("Parallelism = %d, want %d", cfg.Parallelism, 2)
	}
}

func TestParseConfigFromHash_Invalid(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"invalid format", "not-a-hash"},
		{"wrong algorithm", "$argon2i$v=19$m=65536,t=3,p=4$salt$hash"},
		{"wrong parts count", "$argon2id$v=19$salt$hash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfigFromHash(tt.hash)
			if err == nil {
				t.Error("ParseConfigFromHash() expected error for invalid hash")
			}
		})
	}
}

func TestDecodeHash_IncompatibleVersion(t *testing.T) {
	// Create a hash with a fake incompatible version
	hash := "$argon2id$v=99$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g"

	ctx := context.Background()
	h := NewDefault()

	_, err := h.Verify(ctx, "password", hash)
	if err != ErrIncompatibleVersion {
		t.Errorf("Verify() error = %v, want ErrIncompatibleVersion", err)
	}
}

func TestVerify_OversizedHash(t *testing.T) {
	ctx := context.Background()
	h := NewDefault()

	// Create a valid-looking hash but with oversized base64 content
	// This tests the bounds checking for hash length > 1024
	oversizedContent := strings.Repeat("a", 2000) // Will decode to ~1500 bytes
	hash := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$" + oversizedContent

	_, err := h.Verify(ctx, "password", hash)
	if err != ErrInvalidHash {
		t.Errorf("Verify() error = %v, want ErrInvalidHash for oversized hash", err)
	}
}

func BenchmarkHash(b *testing.B) {
	ctx := context.Background()
	h := NewDefault()
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(ctx, password)
	}
}

func BenchmarkVerify(b *testing.B) {
	ctx := context.Background()
	h := NewDefault()
	password := "benchmarkPassword123!"
	hash, _ := h.Hash(ctx, password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Verify(ctx, password, hash)
	}
}
