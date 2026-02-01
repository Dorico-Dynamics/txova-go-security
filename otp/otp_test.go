package otp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Dorico-Dynamics/txova-go-types/contact"

	secerrors "github.com/Dorico-Dynamics/txova-go-security"
)

// mockRedis implements RedisClient for testing.
type mockRedis struct {
	mu      sync.Mutex
	data    map[string]string
	expiry  map[string]time.Time
	errGet  error
	errSet  error
	errDel  error
	errIncr error
}

func newMockRedis() *mockRedis {
	return &mockRedis{
		data:   make(map[string]string),
		expiry: make(map[string]time.Time),
	}
}

func (m *mockRedis) Get(_ context.Context, key string) StringCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errGet != nil {
		return &mockStringCmd{err: m.errGet}
	}

	// Check expiry
	if exp, ok := m.expiry[key]; ok && time.Now().After(exp) {
		delete(m.data, key)
		delete(m.expiry, key)
		return &mockStringCmd{err: errors.New("redis: nil")}
	}

	val, ok := m.data[key]
	if !ok {
		return &mockStringCmd{err: errors.New("redis: nil")}
	}
	return &mockStringCmd{val: val}
}

func (m *mockRedis) Set(_ context.Context, key string, value interface{}, expiration time.Duration) StatusCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errSet != nil {
		return &mockStatusCmd{err: m.errSet}
	}

	m.data[key] = value.(string)
	if expiration > 0 {
		m.expiry[key] = time.Now().Add(expiration)
	}
	return &mockStatusCmd{}
}

func (m *mockRedis) SetNX(_ context.Context, key string, value interface{}, expiration time.Duration) BoolCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.data[key]; exists {
		return &mockBoolCmd{val: false}
	}

	m.data[key] = value.(string)
	if expiration > 0 {
		m.expiry[key] = time.Now().Add(expiration)
	}
	return &mockBoolCmd{val: true}
}

func (m *mockRedis) Del(_ context.Context, keys ...string) IntCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errDel != nil {
		return &mockIntCmd{err: m.errDel}
	}

	var deleted int64
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			delete(m.data, key)
			delete(m.expiry, key)
			deleted++
		}
	}
	return &mockIntCmd{val: deleted}
}

func (m *mockRedis) Incr(_ context.Context, key string) IntCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errIncr != nil {
		return &mockIntCmd{err: m.errIncr}
	}

	var val int64 = 1
	if existing, ok := m.data[key]; ok {
		if v, err := parseInt64(existing); err == nil {
			val = v + 1
		}
	}
	m.data[key] = formatInt64(val)
	return &mockIntCmd{val: val}
}

func (m *mockRedis) Expire(_ context.Context, key string, expiration time.Duration) BoolCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.data[key]; ok {
		m.expiry[key] = time.Now().Add(expiration)
		return &mockBoolCmd{val: true}
	}
	return &mockBoolCmd{val: false}
}

func (m *mockRedis) Exists(_ context.Context, keys ...string) IntCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	var count int64
	for _, key := range keys {
		// Check expiry
		if exp, ok := m.expiry[key]; ok && time.Now().After(exp) {
			delete(m.data, key)
			delete(m.expiry, key)
			continue
		}
		if _, ok := m.data[key]; ok {
			count++
		}
	}
	return &mockIntCmd{val: count}
}

// Mock command implementations.
type mockStringCmd struct {
	val string
	err error
}

func (c *mockStringCmd) Result() (string, error) {
	return c.val, c.err
}

type mockStatusCmd struct {
	err error
}

func (c *mockStatusCmd) Err() error {
	return c.err
}

type mockBoolCmd struct {
	val bool
	err error
}

func (c *mockBoolCmd) Result() (bool, error) {
	return c.val, c.err
}

type mockIntCmd struct {
	val int64
	err error
}

func (c *mockIntCmd) Result() (int64, error) {
	return c.val, c.err
}

func parseInt64(s string) (int64, error) {
	var v int64
	_, err := parseIntHelper(s, &v)
	return v, err
}

func parseIntHelper(s string, v *int64) (int, error) {
	n, err := parsePositiveInt(s)
	*v = int64(n)
	return n, err
}

func parsePositiveInt(s string) (int, error) {
	var result int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid number")
		}
		result = result*10 + int(c-'0')
	}
	return result, nil
}

func formatInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	var result []byte
	for v > 0 {
		result = append([]byte{byte('0' + v%10)}, result...)
		v /= 10
	}
	return string(result)
}

func testPhone(t *testing.T) contact.PhoneNumber {
	t.Helper()
	phone, err := contact.ParsePhoneNumber("+258841234567")
	if err != nil {
		t.Fatalf("failed to parse test phone: %v", err)
	}
	return phone
}

func TestNew(t *testing.T) {
	redis := newMockRedis()

	t.Run("default config", func(t *testing.T) {
		svc := New(redis)
		if svc.config.Length != 6 {
			t.Errorf("expected default length 6, got %d", svc.config.Length)
		}
		if svc.config.Expiry != 5*time.Minute {
			t.Errorf("expected default expiry 5m, got %v", svc.config.Expiry)
		}
		if svc.config.MaxAttempts != 3 {
			t.Errorf("expected default max attempts 3, got %d", svc.config.MaxAttempts)
		}
	})

	t.Run("with options", func(t *testing.T) {
		svc := New(redis,
			WithLength(4),
			WithExpiry(10*time.Minute),
			WithMaxAttempts(5),
			WithLockoutDuration(30*time.Minute),
			WithCooldown(30*time.Second),
			WithKeyPrefix("test"),
		)

		if svc.config.Length != 4 {
			t.Errorf("expected length 4, got %d", svc.config.Length)
		}
		if svc.config.Expiry != 10*time.Minute {
			t.Errorf("expected expiry 10m, got %v", svc.config.Expiry)
		}
		if svc.config.MaxAttempts != 5 {
			t.Errorf("expected max attempts 5, got %d", svc.config.MaxAttempts)
		}
		if svc.config.LockoutDuration != 30*time.Minute {
			t.Errorf("expected lockout 30m, got %v", svc.config.LockoutDuration)
		}
		if svc.config.Cooldown != 30*time.Second {
			t.Errorf("expected cooldown 30s, got %v", svc.config.Cooldown)
		}
		if svc.config.KeyPrefix != "test" {
			t.Errorf("expected prefix 'test', got %s", svc.config.KeyPrefix)
		}
	})

	t.Run("invalid options ignored", func(t *testing.T) {
		svc := New(redis,
			WithLength(0),
			WithLength(-1),
			WithLength(15),
			WithExpiry(0),
			WithMaxAttempts(0),
			WithKeyPrefix(""),
		)

		// Should retain defaults
		if svc.config.Length != 6 {
			t.Errorf("expected default length 6, got %d", svc.config.Length)
		}
	})
}

func TestGenerate(t *testing.T) {
	ctx := context.Background()
	phone := testPhone(t)

	t.Run("successful generation", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis)

		otp, expiry, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(otp) != 6 {
			t.Errorf("expected 6-digit OTP, got %d digits", len(otp))
		}

		// Verify all characters are digits
		for _, c := range otp {
			if c < '0' || c > '9' {
				t.Errorf("OTP contains non-digit: %c", c)
			}
		}

		if expiry.Before(time.Now()) {
			t.Error("expiry should be in the future")
		}
	})

	t.Run("cooldown enforced", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis, WithCooldown(1*time.Hour)) // Long cooldown for testing

		// First generation should succeed
		_, _, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("first generation failed: %v", err)
		}

		// Second generation should fail (cooldown)
		_, _, err = svc.Generate(ctx, phone)
		if err == nil {
			t.Fatal("expected cooldown error")
		}
		if !secerrors.IsOTPCooldown(err) {
			t.Errorf("expected OTPCooldown error, got: %v", err)
		}
	})

	t.Run("custom length", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis, WithLength(4))

		otp, _, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(otp) != 4 {
			t.Errorf("expected 4-digit OTP, got %d digits", len(otp))
		}
	})
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	phone := testPhone(t)

	t.Run("successful verification", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis)

		otp, _, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}

		err = svc.Verify(ctx, phone, otp)
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("invalid OTP", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis)

		_, _, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}

		err = svc.Verify(ctx, phone, "000000")
		if err == nil {
			t.Fatal("expected error for invalid OTP")
		}
		if !secerrors.IsOTPInvalid(err) {
			t.Errorf("expected OTPInvalid error, got: %v", err)
		}
	})

	t.Run("OTP not found", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis)

		err := svc.Verify(ctx, phone, "123456")
		if err == nil {
			t.Fatal("expected error when no OTP exists")
		}
		if !secerrors.IsOTPInvalid(err) {
			t.Errorf("expected OTPInvalid error, got: %v", err)
		}
	})

	t.Run("OTP can only be used once", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis)

		otp, _, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}

		// First verification succeeds
		err = svc.Verify(ctx, phone, otp)
		if err != nil {
			t.Fatalf("first verification failed: %v", err)
		}

		// Second verification fails (OTP was deleted)
		err = svc.Verify(ctx, phone, otp)
		if err == nil {
			t.Fatal("expected error for reused OTP")
		}
	})
}

func TestLockout(t *testing.T) {
	ctx := context.Background()
	phone := testPhone(t)

	t.Run("lockout after max attempts", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis, WithMaxAttempts(3))

		_, _, err := svc.Generate(ctx, phone)
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}

		// Make max attempts with wrong OTP
		for i := 0; i < 3; i++ {
			err = svc.Verify(ctx, phone, "000000")
			if !secerrors.IsOTPInvalid(err) {
				t.Errorf("attempt %d: expected OTPInvalid, got: %v", i+1, err)
			}
		}

		// Next attempt should be locked
		err = svc.Verify(ctx, phone, "000000")
		if !secerrors.IsOTPLocked(err) {
			t.Errorf("expected OTPLocked error, got: %v", err)
		}
	})

	t.Run("IsLocked returns correct status", func(t *testing.T) {
		redis := newMockRedis()
		svc := New(redis, WithMaxAttempts(2))

		_, _, _ = svc.Generate(ctx, phone)

		locked, err := svc.IsLocked(ctx, phone)
		if err != nil {
			t.Fatalf("IsLocked failed: %v", err)
		}
		if locked {
			t.Error("should not be locked initially")
		}

		// Exceed max attempts
		for i := 0; i < 3; i++ {
			_ = svc.Verify(ctx, phone, "000000")
		}

		locked, err = svc.IsLocked(ctx, phone)
		if err != nil {
			t.Fatalf("IsLocked failed: %v", err)
		}
		if !locked {
			t.Error("should be locked after exceeding max attempts")
		}
	})
}

func TestGetAttempts(t *testing.T) {
	ctx := context.Background()
	phone := testPhone(t)

	redis := newMockRedis()
	svc := New(redis)

	// Initially zero
	attempts := svc.GetAttempts(ctx, phone)
	if attempts != 0 {
		t.Errorf("expected 0 attempts, got %d", attempts)
	}

	// Generate and make some attempts
	_, _, _ = svc.Generate(ctx, phone)
	_ = svc.Verify(ctx, phone, "000000")
	_ = svc.Verify(ctx, phone, "000001")

	attempts = svc.GetAttempts(ctx, phone)
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestInvalidate(t *testing.T) {
	ctx := context.Background()
	phone := testPhone(t)

	redis := newMockRedis()
	svc := New(redis)

	otp, _, err := svc.Generate(ctx, phone)
	if err != nil {
		t.Fatalf("generation failed: %v", err)
	}

	// Invalidate the OTP
	err = svc.Invalidate(ctx, phone)
	if err != nil {
		t.Fatalf("invalidation failed: %v", err)
	}

	// Verification should now fail
	err = svc.Verify(ctx, phone, otp)
	if err == nil {
		t.Fatal("expected error after invalidation")
	}
}

func TestGenerateCode(t *testing.T) {
	redis := newMockRedis()
	svc := New(redis)

	// Test uniqueness
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		otp, err := svc.generateCode()
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}
		seen[otp] = struct{}{}
	}

	// Should have mostly unique codes (some collisions possible but rare for 6 digits)
	if len(seen) < 900 {
		t.Errorf("expected mostly unique codes, got only %d unique out of 1000", len(seen))
	}
}

func TestHashOTP(t *testing.T) {
	// Same input produces same hash
	hash1 := hashOTP("123456")
	hash2 := hashOTP("123456")
	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}

	// Different input produces different hash
	hash3 := hashOTP("654321")
	if hash1 == hash3 {
		t.Error("different input should produce different hash")
	}

	// Hash is 64 hex chars (SHA256)
	if len(hash1) != 64 {
		t.Errorf("expected 64 char hash, got %d", len(hash1))
	}
}

func BenchmarkGenerate(b *testing.B) {
	ctx := context.Background()
	redis := newMockRedis()
	svc := New(redis, WithCooldown(0)) // Disable cooldown for benchmark

	phone, _ := contact.ParsePhoneNumber("+258841234567")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.Generate(ctx, phone)
	}
}

func BenchmarkVerify(b *testing.B) {
	ctx := context.Background()
	redis := newMockRedis()
	svc := New(redis)

	phone, _ := contact.ParsePhoneNumber("+258841234567")
	otp, _, _ := svc.Generate(ctx, phone)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset OTP for each iteration
		redis.data["otp:code:"+phone.String()] = hashOTP(otp)
		_ = svc.Verify(ctx, phone, otp)
	}
}
