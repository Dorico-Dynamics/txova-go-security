# txova-go-security Execution Plan

## Overview

Implementation plan for the security utilities library providing password hashing, OTP generation, encryption, token generation, PIN generation, PII masking, and security audit logging for the Txova platform.

**Target Coverage:** > 90%

---

## Internal Dependencies

### txova-go-types
| Package | Types Used | Purpose |
|---------|------------|---------|
| `contact` | `PhoneNumber` | OTP phone validation, masking |
| `contact` | `Email` | Email masking |

### txova-go-core
| Package | Types/Functions Used | Purpose |
|---------|---------------------|---------|
| `errors` | `AppError`, `Code`, error constructors | Structured error handling |
| `errors` | `ValidationError()`, `InvalidCredentials()`, `TokenExpired()` | Security-specific errors |
| `errors` | `InternalErrorWrap()` | Wrap crypto errors without leaking details |
| `logging` | `Logger`, `*Context()` methods | Structured logging with context |
| `logging` | `MaskPhone()`, `MaskEmail()`, `MaskSensitive()` | PII masking in logs |
| `logging` | `PhoneAttr()`, `EmailAttr()`, `SafeAttr()` | Safe log attributes |
| `context` | `RequestID()`, `UserID()`, `CorrelationID()` | Context field extraction |

---

## Progress Summary

| Phase | Status | Commit | Coverage |
|-------|--------|--------|----------|
| Phase 1: Foundation | ✅ Complete | `2720bf6` | 100% |
| Phase 2: Password Hashing | ✅ Complete | `a3b43d3` | 96.5% |
| Phase 3: Token Generation | ✅ Complete | `41323f2` | 93.6% |
| Phase 4: PIN Generation | ✅ Complete | `809e691` | 92.6% |
| Phase 5: Encryption | ✅ Complete | `ac1aab7` | 92.3% |
| Phase 6: PII Masking | ✅ Complete | `3c8397d` | 98.1% |
| Phase 7: OTP Service | ⏳ Pending | - | - |
| Phase 8: Security Audit Logging | ⏳ Pending | - | - |
| Phase 9: Integration & Documentation | ⏳ Pending | - | - |

**Current Branch:** `feature/implementation`

---

## Phase 1: Foundation

### 1.1 Project Setup
- [x] Initialize Go module with `github.com/Dorico-Dynamics/txova-go-security`
- [x] Add external dependencies:
  - `golang.org/x/crypto` (argon2)
- [x] Add internal dependencies:
  - `github.com/Dorico-Dynamics/txova-go-types`
  - `github.com/Dorico-Dynamics/txova-go-core`
- [x] Create package structure: `password/`, `token/`, `pin/`, `encrypt/`, `mask/`, `otp/`, `audit/`
- [x] Set up `.golangci.yml` for linting (copy from txova-go-db)

### 1.2 Common Error Types
- [x] Define security-specific error codes extending `txova-go-core/errors`:
  - `CodeOTPExpired` - OTP has expired
  - `CodeOTPInvalid` - OTP is invalid
  - `CodeOTPLocked` - Account locked due to too many attempts
  - `CodeOTPCooldown` - Must wait before requesting new OTP
  - `CodeEncryptionFailed` - Encryption operation failed
  - `CodeDecryptionFailed` - Decryption operation failed
- [x] Create error constructors for each security error type
- [x] Support `errors.Is()` and `errors.As()` via `txova-go-core/errors` patterns

### 1.3 Tests
- [x] Test error codes and HTTP status mappings
- [x] Test error wrapping and unwrapping

---

## Phase 2: Password Hashing (`password` package)

### 2.1 Argon2id Implementation
- [ ] Implement `Hasher` struct with configuration
- [ ] Implement `Hash(ctx context.Context, password string) (string, error)` using Argon2id
- [ ] Use `crypto/rand` for salt generation (16 bytes)
- [ ] Configure default parameters per OWASP:
  - Memory: 64 MB (65536 KiB)
  - Iterations: 3
  - Parallelism: 4
  - Salt length: 16 bytes
  - Key length: 32 bytes
- [ ] Output PHC-formatted string: `$argon2id$v=19$m=65536,t=3,p=4$salt$hash`

### 2.2 Verification
- [ ] Implement `Verify(ctx context.Context, password, hash string) (bool, error)`
- [ ] Use `crypto/subtle.ConstantTimeCompare` to prevent timing attacks
- [ ] Parse PHC string to extract parameters for verification
- [ ] Support verification of hashes created with different parameters

### 2.3 Parameter Management
- [ ] Implement `NeedsRehash(hash string) (bool, error)` to detect outdated parameters
- [ ] Support configuration via functional options pattern
- [ ] Provide `DefaultConfig()` and `NewDefault()` constructors

### 2.4 Validation
- [ ] Implement `ValidatePassword(password string) error` for basic length validation
- [ ] Constants: `MinPasswordLength = 8`, `MaxPasswordLength = 128`
- [ ] Return `errors.ValidationError()` for invalid passwords

### 2.5 Integration
- [ ] Accept `*logging.Logger` for optional logging (hash timing, etc.)
- [ ] Use `errors.InternalErrorWrap()` for crypto failures

### 2.6 Tests
- [ ] Test hash generation produces valid PHC format
- [ ] Test verification with correct/incorrect passwords
- [ ] Test empty password handling
- [ ] Test parameter upgrade detection (`NeedsRehash`)
- [ ] Test functional options
- [ ] Benchmark hash time (target: 200-500ms)

---

## Phase 3: Token Generation (`token` package) ✅

### 3.1 Secure Random Generation
- [x] Implement `Generate() (string, error)` - 32-byte hex-encoded token (64 chars)
- [x] Implement `GenerateURLSafe() (string, error)` - 32-byte base64url-encoded token
- [x] Implement `GenerateWithLength(bytes int) (string, error)` - configurable length
- [x] Use `crypto/rand` exclusively (never `math/rand`)

### 3.2 Token Hashing for Storage
- [x] Implement `Hash(token string) string` - SHA256 hash (hex-encoded)
- [x] Implement `Compare(token, hashedToken string) bool` - constant-time comparison
- [x] Document: Never store plaintext tokens, always store hash

### 3.3 Token Type Helpers
- [x] Define constants for standard token lengths:
  - `SessionTokenBytes = 32`
  - `RefreshTokenBytes = 32`
  - `ResetTokenBytes = 32`
  - `VerificationTokenBytes = 32`
  - `APIKeyBytes = 32`
- [x] Provide type-specific generators: `GenerateSessionToken()`, `GenerateAPIKey()`, etc.

### 3.4 Tests
- [x] Test token uniqueness (generate 10000 tokens, no duplicates)
- [x] Test token length and format (hex, base64url)
- [x] Test URL-safe encoding (no `+`, `/`, `=`)
- [x] Test hash comparison (correct/incorrect)
- [x] Benchmark generation speed

---

## Phase 4: PIN Generation (`pin` package) ✅

### 4.1 Secure PIN Generation
- [x] Implement `Generate() (string, error)` - 4-digit PIN
- [x] Use `crypto/rand` for cryptographically secure random digits
- [x] Retry up to `MaxRetries = 10` if generated PIN fails validation

### 4.2 PIN Validation Rules
- [x] Implement `Validate(pin string) error`
- [x] Return `errors.ValidationError()` with specific reason
- [x] Validation rules:
  - Must be exactly 4 digits
  - No sequential ascending: 0123, 1234, 2345, 3456, 4567, 5678, 6789
  - No sequential descending: 9876, 8765, 7654, 6543, 5432, 4321, 3210
  - No repeated digits: 0000, 1111, 2222, ..., 9999
  - Not in blacklist

### 4.3 Blacklist
- [x] Define blacklist per PRD:
  ```
  0000, 1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 9999,
  1234, 2345, 3456, 4567, 5678, 6789, 4321, 3210, 0123
  ```
- [x] Support custom blacklist via configuration

### 4.4 Tests
- [x] Test all generated PINs pass validation (generate 10000)
- [x] Test each blacklisted PIN is rejected
- [x] Test sequential detection (ascending and descending)
- [x] Test repeated digit detection
- [x] Test retry logic exhaustion returns error
- [x] Test format validation (non-digits, wrong length)

---

## Phase 5: Encryption (`encrypt` package) ✅

### 5.1 AES-256-GCM Implementation
- [x] Implement `Cipher` struct holding keys
- [x] Implement `Encrypt(plaintext []byte) (string, error)`
- [x] Implement `Decrypt(ciphertext string) ([]byte, error)`
- [x] Use AES-256-GCM (authenticated encryption with associated data)
- [x] Generate unique 12-byte nonce per encryption using `crypto/rand`
- [x] Never reuse nonce with same key

### 5.2 Ciphertext Format
- [x] Format: `{key_id}:{nonce_base64}:{ciphertext_base64}`
- [x] Example: `primary:dGVzdG5vbmNl:Y2lwaGVydGV4dA==`
- [x] Parse format on decryption to extract key_id and nonce

### 5.3 Key Management
- [x] Support 256-bit (32-byte) keys only
- [x] Implement `New(primaryKeyID string, primaryKey []byte) (*Cipher, error)`
- [x] Implement `AddKey(keyID string, key []byte) error` for rotation
- [x] Implement `SetPrimaryKey(keyID string) error`
- [x] Primary key used for encryption, all keys available for decryption

### 5.4 Field-Level Encryption Helpers
- [x] Implement `EncryptField(value string) (string, error)` - string wrapper
- [x] Implement `DecryptField(encrypted string) (string, error)` - string wrapper
- [x] Handle empty strings gracefully (return empty, not error)

### 5.5 Error Handling
- [x] Use `errors.New(CodeEncryptionFailed, ...)` for encryption errors
- [x] Use `errors.New(CodeDecryptionFailed, ...)` for decryption errors
- [x] Never expose internal crypto errors to callers

### 5.6 Tests
- [x] Test encrypt/decrypt roundtrip (various sizes)
- [x] Test unique nonce per encryption (encrypt same plaintext twice)
- [x] Test key rotation (encrypt with new key, decrypt with old key)
- [x] Test tamper detection (modify ciphertext, should fail)
- [x] Test invalid key ID handling
- [x] Test invalid ciphertext format handling
- [x] Test empty plaintext/ciphertext
- [x] Benchmark encryption latency (target: < 1ms)

---

## Phase 6: PII Masking (`mask` package) ✅

### 6.1 Phone Number Masking
- [x] Implement `Phone(phone string) string`
- [x] Accept both `string` and integration with `contact.PhoneNumber`
- [x] Format: `+258****4567` (preserve country code prefix and last 4 digits)
- [x] Handle various formats (with/without +, spaces, dashes)
- [x] Return empty string for empty input

### 6.2 Email Masking
- [x] Implement `Email(email string) string`
- [x] Accept both `string` and integration with `contact.Email`
- [x] Format: `u***@example.com` (first char of local part + mask + full domain)
- [x] Handle short local parts (1-2 chars): mask entirely except first char
- [x] Return empty string for empty input

### 6.3 Name Masking
- [x] Implement `Name(name string) string`
- [x] Format: `J*** S****` (first char of each word + mask based on remaining length)
- [x] Handle single names: `John` → `J***`
- [x] Handle multiple names: `John Smith Jr` → `J*** S**** J*`
- [x] Preserve word structure

### 6.4 Card Number Masking
- [x] Implement `Card(number string) string`
- [x] Format: `****1111` (mask all but last 4 digits)
- [x] Strip non-digits before masking
- [x] Handle various formats (spaces, dashes)

### 6.5 ID Document Masking
- [x] Implement `ID(id string) string`
- [x] Format: `AB***456` (first 2 chars + mask + last 3 chars)
- [x] Handle variable length IDs
- [x] For short IDs (< 5 chars), mask middle portion

### 6.6 Configuration
- [x] Support configurable mask character via `WithMaskChar(char rune)` option
- [x] Default mask character: `*`
- [x] Implement `Masker` struct for configured masking

### 6.7 Tests
- [x] Test each masking function with various inputs
- [x] Test edge cases: empty, single char, very long
- [x] Test with `contact.PhoneNumber` and `contact.Email` types
- [x] Test custom mask character
- [x] Test format preservation (spaces, structure)

---

## Phase 7: OTP Service (`otp` package)

### 7.1 Dependencies
- [ ] Require Redis client interface for storage
- [ ] Accept `*logging.Logger` for logging
- [ ] Use `contact.PhoneNumber` for phone validation

### 7.2 OTP Generation
- [ ] Implement `Service` struct with config and Redis client
- [ ] Implement `Generate(ctx context.Context, phone contact.PhoneNumber) (string, time.Time, error)`
- [ ] Generate 6-digit OTP using `crypto/rand`
- [ ] Check cooldown before generating (return `CodeOTPCooldown` error if active)
- [ ] Hash OTP with SHA256 before storing (never store plaintext)
- [ ] Store in Redis with TTL: `otp:{phone}` → hashed OTP (5 minutes)
- [ ] Set cooldown: `otp:cooldown:{phone}` (60 seconds)
- [ ] Return plaintext OTP to caller (for sending via SMS)
- [ ] Return expiry time

### 7.3 OTP Verification
- [ ] Implement `Verify(ctx context.Context, phone contact.PhoneNumber, code string) error`
- [ ] Check lockout first (return `CodeOTPLocked` if locked)
- [ ] Increment attempt counter on every call (success or fail)
- [ ] Hash provided code and compare with stored hash
- [ ] On success: delete OTP and attempts keys
- [ ] On failure: check if max attempts reached, set lockout if so
- [ ] Return generic errors (don't reveal if phone exists)

### 7.4 Rate Limiting & Lockout
- [ ] Key patterns:
  - `otp:{phone}` - hashed OTP (TTL: 5m)
  - `otp:attempts:{phone}` - attempt counter (TTL: 15m)
  - `otp:lockout:{phone}` - lockout flag (TTL: 15m)
  - `otp:cooldown:{phone}` - cooldown flag (TTL: 60s)
- [ ] Implement `IsLocked(ctx context.Context, phone contact.PhoneNumber) (bool, error)`
- [ ] Implement `GetAttempts(ctx context.Context, phone contact.PhoneNumber) (int, error)`
- [ ] Implement `Invalidate(ctx context.Context, phone contact.PhoneNumber) error`

### 7.5 Configuration
- [ ] `Config` struct with:
  - `Length int` (default: 6)
  - `Expiry time.Duration` (default: 5m)
  - `MaxAttempts int` (default: 3)
  - `LockoutDuration time.Duration` (default: 15m)
  - `Cooldown time.Duration` (default: 60s)
  - `KeyPrefix string` (default: "otp")
- [ ] Functional options: `WithLength()`, `WithExpiry()`, etc.

### 7.6 Logging Integration
- [ ] Log OTP generation (masked phone, expiry) at INFO level
- [ ] Log verification attempts (masked phone, success/fail) at INFO/WARN
- [ ] Log lockouts at WARN level
- [ ] Use `logging.PhoneAttr()` for phone numbers

### 7.7 Tests
- [ ] Test OTP generation format (6 digits)
- [ ] Test OTP verification (correct/incorrect)
- [ ] Test OTP expiry
- [ ] Test attempt counting
- [ ] Test lockout after max attempts
- [ ] Test lockout duration
- [ ] Test cooldown enforcement
- [ ] Test invalidation
- [ ] Integration test with Redis (testcontainers)

---

## Phase 8: Security Audit Logging (`audit` package)

### 8.1 Event Types
- [ ] Define `EventType` enum:
  ```go
  EventLoginSuccess     EventType = "LOGIN_SUCCESS"
  EventLoginFailed      EventType = "LOGIN_FAILED"
  EventPasswordChanged  EventType = "PASSWORD_CHANGED"
  EventOTPSent          EventType = "OTP_SENT"
  EventOTPVerified      EventType = "OTP_VERIFIED"
  EventOTPFailed        EventType = "OTP_FAILED"
  EventOTPLocked        EventType = "OTP_LOCKED"
  EventTokenRevoked     EventType = "TOKEN_REVOKED"
  EventPermissionDenied EventType = "PERMISSION_DENIED"
  EventSuspiciousActivity EventType = "SUSPICIOUS_ACTIVITY"
  ```

### 8.2 Severity Levels
- [ ] Define `Severity` enum: `INFO`, `WARN`, `ALERT`
- [ ] Map events to default severity:
  - INFO: LoginSuccess, PasswordChanged, OTPSent, OTPVerified, TokenRevoked
  - WARN: LoginFailed, OTPFailed, OTPLocked, PermissionDenied
  - ALERT: SuspiciousActivity

### 8.3 Event Structure
- [ ] Define `Event` struct:
  ```go
  type Event struct {
      Type      EventType
      Severity  Severity
      UserID    string  // Always masked
      Phone     string  // Always masked
      Email     string  // Always masked
      IPAddress string
      UserAgent string
      Timestamp time.Time
      Details   map[string]any
  }
  ```

### 8.4 Audit Logger
- [ ] Implement `Logger` struct wrapping `*logging.Logger`
- [ ] Implement `Log(ctx context.Context, event Event)`
- [ ] Auto-mask PII fields using `mask` package
- [ ] Extract context fields (request_id, correlation_id)
- [ ] Format as structured JSON

### 8.5 Alert Handling
- [ ] Define `AlertHandler` interface: `Handle(ctx context.Context, event Event) error`
- [ ] Implement `WithAlertHandler(handler AlertHandler)` option
- [ ] Invoke handler for ALERT severity events
- [ ] Provide no-op default handler

### 8.6 Convenience Methods
- [ ] `LogLoginSuccess(ctx, userID, ip, userAgent)`
- [ ] `LogLoginFailed(ctx, identifier, ip, userAgent, reason)`
- [ ] `LogOTPSent(ctx, phone)`
- [ ] `LogOTPVerified(ctx, phone)`
- [ ] `LogOTPFailed(ctx, phone, reason)`
- [ ] `LogOTPLocked(ctx, phone)`
- [ ] etc.

### 8.7 Tests
- [ ] Test event logging format
- [ ] Test severity mapping
- [ ] Test PII auto-masking
- [ ] Test alert handler invocation
- [ ] Test context field extraction

---

## Phase 9: Integration & Documentation

### 9.1 Integration Testing
- [ ] Set up testcontainers for Redis
- [ ] Integration tests for OTP service with real Redis
- [ ] End-to-end tests for password hash/verify flow
- [ ] End-to-end tests for encrypt/decrypt with key rotation

### 9.2 Final Validation
- [ ] Run full test suite: `go test -race -cover ./...`
- [ ] Verify > 90% coverage target
- [ ] Run linting: `golangci-lint run ./...`
- [ ] Run security analysis: `gosec ./...`
- [ ] Run vet: `go vet ./...`
- [ ] Fix all issues

### 9.3 Documentation
- [ ] Write README.md with:
  - Overview and features
  - Installation
  - Quick start examples
  - Package descriptions
- [ ] Write USAGE.md with:
  - Detailed examples for each package
  - Configuration options
  - Security best practices
  - Integration patterns
- [ ] Ensure all exported types/functions have godoc comments

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
| All exports documented | Required |
