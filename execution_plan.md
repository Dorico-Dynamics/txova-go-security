# txova-go-security Execution Plan

## Overview

Implementation plan for the security utilities library providing password hashing, OTP generation, encryption, token generation, PIN generation, PII masking, and security audit logging for the Txova platform.

**Target Coverage:** > 90%
**Dependencies:** `txova-go-types`, `txova-go-core`

---

## Progress Summary

| Phase | Status | Commit | Coverage |
|-------|--------|--------|----------|
| Phase 1: Foundation | ⏳ Pending | - | - |
| Phase 2: Password Hashing | ⏳ Pending | - | - |
| Phase 3: Token Generation | ⏳ Pending | - | - |
| Phase 4: PIN Generation | ⏳ Pending | - | - |
| Phase 5: Encryption | ⏳ Pending | - | - |
| Phase 6: PII Masking | ⏳ Pending | - | - |
| Phase 7: OTP Service | ⏳ Pending | - | - |
| Phase 8: Security Audit Logging | ⏳ Pending | - | - |
| Phase 9: Integration & Documentation | ⏳ Pending | - | - |

**Current Branch:** `feature/implementation`

---

## Phase 1: Foundation

### 1.1 Project Setup
- [ ] Initialize Go module with `github.com/Dorico-Dynamics/txova-go-security`
- [ ] Add external dependencies: `golang.org/x/crypto/argon2`
- [ ] Add internal dependencies: `txova-go-types`, `txova-go-core`
- [ ] Create package structure: `password/`, `token/`, `pin/`, `encrypt/`, `mask/`, `otp/`, `audit/`
- [ ] Set up `.golangci.yml` for linting

### 1.2 Common Error Types
- [ ] Define security-specific error codes compatible with `txova-go-core/errors`
- [ ] Create base error types for each package
- [ ] Support `errors.Is()` and `errors.As()` for error checking

---

## Phase 2: Password Hashing (`password` package)

### 2.1 Argon2id Implementation
- [ ] Implement `Hash(password string) (string, error)` using Argon2id
- [ ] Use crypto/rand for salt generation (16 bytes)
- [ ] Configure parameters: Memory=64MB, Iterations=3, Parallelism=4, KeyLength=32 bytes
- [ ] Output PHC-formatted string: `$argon2id$v=19$m=65536,t=3,p=4$salt$hash`

### 2.2 Verification
- [ ] Implement `Verify(password, hash string) (bool, error)`
- [ ] Use constant-time comparison (`subtle.ConstantTimeCompare`)
- [ ] Parse PHC string to extract parameters
- [ ] Support verification of hashes with different parameters

### 2.3 Parameter Management
- [ ] Implement `NeedsRehash(hash string) bool` to detect outdated parameters
- [ ] Support configuration via functional options
- [ ] Provide sensible defaults matching OWASP recommendations

### 2.4 Validation
- [ ] Implement `ValidatePassword(password string) error` for basic validation
- [ ] Configurable minimum/maximum length constraints

### 2.5 Tests
- [ ] Test hash generation produces valid PHC format
- [ ] Test verification with correct/incorrect passwords
- [ ] Test constant-time comparison (no timing leaks)
- [ ] Test parameter upgrade detection
- [ ] Benchmark hash time (target: 200-500ms)

---

## Phase 3: Token Generation (`token` package)

### 3.1 Secure Random Generation
- [ ] Implement `Generate() (string, error)` - 32-byte hex-encoded token
- [ ] Implement `GenerateURLSafe() (string, error)` - 32-byte base64url-encoded token
- [ ] Implement `GenerateWithLength(bytes int) (string, error)` - configurable length
- [ ] Use crypto/rand exclusively

### 3.2 Token Hashing
- [ ] Implement `Hash(token string) string` - SHA256 hash for storage
- [ ] Implement `Compare(token, hash string) bool` - constant-time comparison
- [ ] Never store plaintext tokens

### 3.3 Token Types
- [ ] Define constants for token lengths (session, refresh, reset, verification, API key)
- [ ] Provide type-specific generators for clarity

### 3.4 Tests
- [ ] Test token uniqueness (no collisions in large sample)
- [ ] Test token length and format
- [ ] Test URL-safe encoding
- [ ] Test hash comparison

---

## Phase 4: PIN Generation (`pin` package)

### 4.1 Secure PIN Generation
- [ ] Implement `Generate() (string, error)` - 4-digit PIN
- [ ] Use crypto/rand for generation
- [ ] Retry up to 10 times if PIN fails validation rules

### 4.2 PIN Validation Rules
- [ ] Implement `Validate(pin string) error`
- [ ] Reject sequential PINs: 1234, 2345, 3456, 4567, 5678, 6789
- [ ] Reject reverse sequential: 4321, 5432, 6543, 7654, 8765, 9876, 3210
- [ ] Reject repeated digits: 0000, 1111, 2222, ..., 9999
- [ ] Reject common PINs: 0000, 1234, 0123 (blacklist)

### 4.3 Blacklist Management
- [ ] Define comprehensive blacklist based on PRD
- [ ] Allow extension of blacklist via configuration

### 4.4 Tests
- [ ] Test generated PINs pass all validation rules
- [ ] Test all blacklisted PINs are rejected
- [ ] Test sequential detection
- [ ] Test retry logic on invalid generation

---

## Phase 5: Encryption (`encrypt` package)

### 5.1 AES-256-GCM Implementation
- [ ] Implement `Encrypt(plaintext []byte) ([]byte, error)`
- [ ] Implement `Decrypt(ciphertext []byte) ([]byte, error)`
- [ ] Use AES-256-GCM (authenticated encryption)
- [ ] Generate unique 12-byte nonce per encryption using crypto/rand

### 5.2 Key Management
- [ ] Support 256-bit (32-byte) keys
- [ ] Include key ID in ciphertext for rotation support
- [ ] Ciphertext format: `{key_id}:{nonce_base64}:{ciphertext_base64}`
- [ ] Support multiple keys for decryption (rotation)

### 5.3 Field-Level Encryption
- [ ] Implement `EncryptField(value string) (string, error)` - string-friendly wrapper
- [ ] Implement `DecryptField(encrypted string) (string, error)`
- [ ] Handle empty values gracefully

### 5.4 Key Rotation Support
- [ ] Support decryption with old keys during rotation period
- [ ] Implement `AddKey(keyID string, key []byte)` for key registry
- [ ] Implement `SetPrimaryKey(keyID string)` for encryption key selection

### 5.5 Tests
- [ ] Test encrypt/decrypt roundtrip
- [ ] Test unique nonce per encryption
- [ ] Test key rotation (encrypt with new, decrypt with old)
- [ ] Test tamper detection (GCM authentication)
- [ ] Test invalid ciphertext handling

---

## Phase 6: PII Masking (`mask` package)

### 6.1 Phone Number Masking
- [ ] Implement `Phone(phone string) string`
- [ ] Format: `+258****4567` (preserve country code and last 4)
- [ ] Handle various phone formats

### 6.2 Email Masking
- [ ] Implement `Email(email string) string`
- [ ] Format: `u***@example.com` (first char + mask + domain)
- [ ] Handle edge cases (short local parts)

### 6.3 Name Masking
- [ ] Implement `Name(name string) string`
- [ ] Format: `J*** S****` (first char of each word + mask)
- [ ] Handle single names, multiple names

### 6.4 Card Number Masking
- [ ] Implement `Card(number string) string`
- [ ] Format: `****1111` (last 4 only)
- [ ] Strip non-digits before masking

### 6.5 ID Document Masking
- [ ] Implement `ID(id string) string`
- [ ] Format: `AB***456` (first 2 + mask + last 3)
- [ ] Handle variable length IDs

### 6.6 Auto-Detection
- [ ] Implement `Auto(value string, dataType DataType) string`
- [ ] Support configurable mask character (default: `*`)

### 6.7 Tests
- [ ] Test each masking function with various inputs
- [ ] Test edge cases (empty, very short, very long)
- [ ] Test mask character configuration

---

## Phase 7: OTP Service (`otp` package)

### 7.1 OTP Generation
- [ ] Implement `Generate(ctx context.Context, phone string) (string, time.Time, error)`
- [ ] Generate 6-digit OTP using crypto/rand
- [ ] Hash OTP before storing (never store plaintext)
- [ ] Return expiry time

### 7.2 OTP Verification
- [ ] Implement `Verify(ctx context.Context, phone, code string) (bool, error)`
- [ ] Increment attempt counter on every verification (success or fail)
- [ ] Clear OTP after successful verification
- [ ] Return generic errors (don't reveal if phone exists)

### 7.3 Rate Limiting & Lockout
- [ ] Implement cooldown between requests (60 seconds)
- [ ] Implement max attempts (3) before lockout
- [ ] Implement lockout duration (15 minutes)
- [ ] Implement `IsLocked(ctx context.Context, phone string) (bool, error)`
- [ ] Implement `GetAttempts(ctx context.Context, phone string) (int, error)`

### 7.4 Redis Storage
- [ ] Key patterns:
  - `otp:{phone}` - hashed OTP code (TTL: 5m)
  - `otp:attempts:{phone}` - attempt counter (TTL: 15m)
  - `otp:lockout:{phone}` - lockout flag (TTL: 15m)
  - `otp:cooldown:{phone}` - rate limit (TTL: 60s)
- [ ] Implement `Invalidate(ctx context.Context, phone string) error`

### 7.5 Configuration
- [ ] Configurable OTP length (default: 6)
- [ ] Configurable expiry (default: 5 minutes)
- [ ] Configurable max attempts (default: 3)
- [ ] Configurable lockout duration (default: 15 minutes)
- [ ] Configurable cooldown (default: 60 seconds)

### 7.6 Tests
- [ ] Test OTP generation format
- [ ] Test OTP verification (correct/incorrect)
- [ ] Test attempt counting
- [ ] Test lockout after max attempts
- [ ] Test cooldown enforcement
- [ ] Test OTP expiry

---

## Phase 8: Security Audit Logging (`audit` package)

### 8.1 Event Types
- [ ] Define event types:
  - `LOGIN_SUCCESS`, `LOGIN_FAILED`
  - `PASSWORD_CHANGED`
  - `OTP_SENT`, `OTP_VERIFIED`, `OTP_FAILED`, `OTP_LOCKED`
  - `TOKEN_REVOKED`
  - `PERMISSION_DENIED`
  - `SUSPICIOUS_ACTIVITY`

### 8.2 Severity Levels
- [ ] Define severity: `INFO`, `WARN`, `ALERT`
- [ ] Map events to appropriate severity

### 8.3 Audit Logger
- [ ] Implement `Log(ctx context.Context, event Event)` 
- [ ] Include standard fields: event_type, severity, user_id (masked), ip_address, user_agent, timestamp
- [ ] Support additional event-specific details
- [ ] Integrate with `txova-go-core/logging`

### 8.4 Alert Handling
- [ ] Send ALERT events to monitoring (hook interface)
- [ ] Support configurable alert handlers

### 8.5 Safety
- [ ] Never log sensitive data (passwords, tokens, OTPs)
- [ ] Always mask PII in logs using `mask` package
- [ ] Structured JSON format

### 8.6 Tests
- [ ] Test event logging format
- [ ] Test severity mapping
- [ ] Test PII masking in logs
- [ ] Test alert handler invocation

---

## Phase 9: Integration & Documentation

### 9.1 Integration Testing
- [ ] Integration tests for OTP with Redis (testcontainers)
- [ ] End-to-end tests for password hash/verify flow
- [ ] End-to-end tests for encrypt/decrypt flow

### 9.2 Final Validation
- [ ] Run full test suite with coverage report
- [ ] Verify > 90% coverage target
- [ ] Run `golangci-lint` with comprehensive ruleset
- [ ] Run `gosec` for security analysis
- [ ] Fix any issues

### 9.3 Documentation
- [ ] Write README.md with quick start guide
- [ ] Write USAGE.md with detailed examples for each package
- [ ] Ensure all exported types and functions have godoc comments
- [ ] Document security considerations and best practices

---

## Success Criteria

| Metric | Target |
|--------|--------|
| Test coverage | > 90% |
| Password hash time | 200-500ms |
| Encryption latency | < 1ms |
| OTP verification rate | > 95% |
| Zero plaintext leaks | Required |
| Zero critical linting issues | Required |
| All gosec issues resolved | Required |
