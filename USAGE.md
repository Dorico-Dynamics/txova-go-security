# txova-go-security Usage Guide

Detailed usage examples and best practices for the security utilities library.

## Table of Contents

- [Password Hashing](#password-hashing)
- [Token Generation](#token-generation)
- [PIN Generation](#pin-generation)
- [Encryption](#encryption)
- [PII Masking](#pii-masking)
- [OTP Service](#otp-service)
- [Audit Logging](#audit-logging)
- [Error Handling](#error-handling)

---

## Password Hashing

The `password` package provides Argon2id password hashing with PHC string format output.

### Basic Usage

```go
import (
    "context"
    "github.com/Dorico-Dynamics/txova-go-security/password"
)

func main() {
    ctx := context.Background()
    
    // Create hasher with default OWASP parameters
    hasher := password.NewDefault()
    
    // Hash a password
    hash, err := hasher.Hash(ctx, "secure-password-123")
    if err != nil {
        log.Fatal(err)
    }
    // Output: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    
    // Verify password
    valid, err := hasher.Verify(ctx, "secure-password-123", hash)
    if err != nil {
        log.Fatal(err)
    }
    if !valid {
        log.Fatal("invalid password")
    }
}
```

### Password Validation

```go
// Validate password before hashing (8-128 characters)
if err := password.ValidatePassword(userInput); err != nil {
    // Return validation error to user
}
```

### Parameter Upgrade Detection

```go
// Check if hash uses outdated parameters
needsRehash, err := hasher.NeedsRehash(storedHash)
if needsRehash {
    // Re-hash with current parameters after successful login
    newHash, _ := hasher.Hash(ctx, password)
    // Update stored hash in database
}
```

### Custom Configuration

```go
hasher := password.New(
    password.WithMemory(128*1024),  // 128 MB
    password.WithIterations(4),
    password.WithParallelism(8),
    password.WithKeyLength(64),
)
```

---

## Token Generation

The `token` package provides cryptographically secure token generation.

### Token Types

```go
import "github.com/Dorico-Dynamics/txova-go-security/token"

// Session tokens (32 bytes, hex encoded = 64 chars)
sessionToken, _ := token.GenerateSessionToken()

// API keys
apiKey, _ := token.GenerateAPIKey()

// Refresh tokens
refreshToken, _ := token.GenerateRefreshToken()

// Password reset tokens
resetToken, _ := token.GenerateResetToken()

// Email verification tokens
verifyToken, _ := token.GenerateVerificationToken()
```

### URL-Safe Tokens

```go
// Base64url encoded (no +, /, or = characters)
urlSafeToken, _ := token.GenerateURLSafe()
```

### Secure Token Storage

```go
// NEVER store plaintext tokens - always hash them
hashedToken := token.Hash(plainToken)

// Store hashedToken in database
db.StoreToken(userID, hashedToken)

// When verifying, hash the provided token and compare
providedHash := token.Hash(providedToken)
if providedHash != storedHash {
    return errors.New("invalid token")
}

// Or use constant-time comparison
if !token.Compare(providedToken, storedHash) {
    return errors.New("invalid token")
}
```

### Token Validation

```go
// Validate hex-encoded tokens (32 bytes = 64 hex chars)
if !token.IsValidHexToken(t, 32) {
    return errors.New("invalid token format")
}

// Validate base64url tokens (32 bytes)
if !token.IsValidBase64Token(t, 32) {
    return errors.New("invalid token format")
}
```

---

## PIN Generation

The `pin` package generates secure 4-digit PINs for ride verification.

### Basic Usage

```go
import "github.com/Dorico-Dynamics/txova-go-security/pin"

// Generate PIN
code, err := pin.Generate()
if err != nil {
    log.Fatal(err)
}
// Output: e.g., "5839"

// Validate PIN
if err := pin.Validate(userInput); err != nil {
    // Invalid PIN format or blacklisted
}
```

### Validation Rules

PINs are rejected if they:
- Are not exactly 4 digits
- Contain non-digit characters
- Are sequential ascending (0123, 1234, etc.)
- Are sequential descending (9876, 8765, etc.)
- Are repeated digits (0000, 1111, etc.)
- Are in the blacklist

### Custom Blacklist

```go
generator := pin.NewGenerator(
    pin.WithAdditionalBlacklist("1357", "2468"),
)
code, _ := generator.Generate()
```

---

## Encryption

The `encrypt` package provides AES-256-GCM encryption with key rotation.

### Basic Usage

```go
import "github.com/Dorico-Dynamics/txova-go-security/encrypt"

// Generate a key
key, _ := encrypt.GenerateKey()

// Create cipher
cipher, err := encrypt.New("key-v1", key)
if err != nil {
    log.Fatal(err)
}

// Encrypt
ciphertext, err := cipher.Encrypt([]byte("sensitive data"))
// Output: key-v1:<nonce>:<ciphertext>

// Decrypt
plaintext, err := cipher.Decrypt(ciphertext)
```

### Field-Level Encryption

```go
// String convenience methods
encrypted, _ := cipher.EncryptField("user@example.com")
email, _ := cipher.DecryptField(encrypted)

// Empty strings are handled gracefully
empty, _ := cipher.EncryptField("")  // Returns ""
```

### Key Rotation

```go
// 1. Add new key
newKey, _ := encrypt.GenerateKey()
cipher.AddKey("key-v2", newKey)

// 2. Set as primary (new encryptions use this key)
cipher.SetPrimaryKey("key-v2")

// 3. Old data still decrypts (cipher retains old keys)
plaintext, _ := cipher.Decrypt(oldCiphertext)  // Uses key-v1

// 4. Re-encrypt data with new key (during migration)
newCiphertext, _ := cipher.Encrypt(plaintext)  // Uses key-v2
```

### Ciphertext Format

```text
{key_id}:{nonce_base64}:{ciphertext_base64}

Example:
key-v1:dGVzdG5vbmNl:Y2lwaGVydGV4dA==
```

---

## PII Masking

The `mask` package provides PII masking for safe logging and display.

### Phone Numbers

```go
import "github.com/Dorico-Dynamics/txova-go-security/mask"

mask.Phone("+258841234567")     // +2588****4567
mask.Phone("+1 555 123 4567")   // +1555***4567
mask.Phone("841234567")         // *****4567
```

### Email Addresses

```go
mask.Email("user@example.com")      // u***@example.com
mask.Email("ab@test.com")           // a***@test.com
mask.Email("longname@domain.org")   // l*******@domain.org
```

### Names

```go
mask.Name("John")              // J***
mask.Name("John Smith")        // J*** S****
mask.Name("John Smith Jr")     // J*** S**** J*
```

### Card Numbers

```go
mask.Card("4111111111111111")       // ************1111
mask.Card("4111-1111-1111-1111")    // ************1111
```

### ID Documents

```go
mask.ID("AB1234567")     // AB****567
mask.ID("123456789012")  // 12*******012
```

### Custom Mask Character

```go
masker := mask.NewMasker(mask.WithMaskChar('#'))
masker.Phone("+258841234567")  // +2588####4567
```

### Integration with Contact Types

```go
import "github.com/Dorico-Dynamics/txova-go-types/contact"

phone, _ := contact.ParsePhoneNumber("+258841234567")
masked := mask.PhoneNumber(phone)

email, _ := contact.ParseEmail("user@example.com")
masked := mask.EmailAddress(email)
```

---

## OTP Service

The `otp` package provides Redis-backed OTP with rate limiting and lockout.

### Setup

```go
import (
    "github.com/redis/go-redis/v9"
    "github.com/Dorico-Dynamics/txova-go-security/otp"
)

// Create Redis client
redisClient := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})

// Create OTP service
service := otp.New(redisClient,
    otp.WithLength(6),
    otp.WithExpiry(5*time.Minute),
    otp.WithMaxAttempts(3),
    otp.WithLockoutDuration(15*time.Minute),
    otp.WithCooldown(60*time.Second),
)
```

### Generate OTP

```go
phone, _ := contact.ParsePhoneNumber("+258841234567")

code, expiry, err := service.Generate(ctx, phone)
if err != nil {
    if security.IsOTPCooldown(err) {
        // User must wait before requesting new OTP
        return errors.New("please wait before requesting a new code")
    }
    return err
}

// Send code via SMS
sms.Send(phone, fmt.Sprintf("Your code is: %s", code))
```

### Verify OTP

```go
err := service.Verify(ctx, phone, userProvidedCode)
if err != nil {
    if security.IsOTPInvalid(err) {
        return errors.New("invalid code")
    }
    if security.IsOTPLocked(err) {
        return errors.New("too many attempts, please try again later")
    }
    return err
}

// OTP verified successfully
```

### Check Status

```go
// Check if locked out
locked, _ := service.IsLocked(ctx, phone)

// Get attempt count
attempts := service.GetAttempts(ctx, phone)

// Manually invalidate OTP
service.Invalidate(ctx, phone)
```

### Redis Key Patterns

```text
otp:code:{phone}      - Hashed OTP (TTL: 5m)
otp:attempts:{phone}  - Attempt counter (TTL: 15m)
otp:lockout:{phone}   - Lockout flag (TTL: 15m)
otp:cooldown:{phone}  - Cooldown flag (TTL: 60s)
```

---

## Audit Logging

The `audit` package provides security event logging with automatic PII masking.

### Setup

```go
import (
    "github.com/Dorico-Dynamics/txova-go-core/logging"
    "github.com/Dorico-Dynamics/txova-go-security/audit"
)

logger := logging.New(logging.ProductionConfig("my-service"))
auditLog := audit.New(logger)
```

### Log Security Events

```go
// Login events
auditLog.LogLoginSuccess(ctx, userID, ip, userAgent)
auditLog.LogLoginFailed(ctx, email, ip, userAgent, "invalid password")

// Password events
auditLog.LogPasswordChanged(ctx, userID, ip)

// OTP events
auditLog.LogOTPSent(ctx, phone)
auditLog.LogOTPVerified(ctx, phone)
auditLog.LogOTPFailed(ctx, phone, "invalid code")
auditLog.LogOTPLocked(ctx, phone)

// Token events
auditLog.LogTokenRevoked(ctx, userID, "refresh", ip)

// Access events
auditLog.LogPermissionDenied(ctx, userID, "/admin", "DELETE", ip)

// Suspicious activity (triggers alert handler)
auditLog.LogSuspiciousActivity(ctx, userID, "multiple_failed_logins", ip, userAgent, map[string]any{
    "attempt_count": 10,
    "time_window":   "5m",
})
```

### Custom Events

```go
auditLog.Log(ctx, audit.Event{
    Type:      audit.EventType("CUSTOM_EVENT"),
    Severity:  audit.SeverityWarn,
    UserID:    userID,
    IPAddress: ip,
    Details: map[string]any{
        "action": "export_data",
        "rows":   1000,
    },
})
```

### Alert Handler

```go
type SlackAlertHandler struct {
    webhookURL string
}

func (h *SlackAlertHandler) Handle(ctx context.Context, event audit.Event) error {
    // Send to Slack, PagerDuty, etc.
    return sendSlackAlert(h.webhookURL, event)
}

auditLog := audit.New(logger, 
    audit.WithAlertHandler(&SlackAlertHandler{webhookURL: "..."}),
)
```

---

## Error Handling

The library provides security-specific error types that integrate with `txova-go-core/errors`.

### Error Types

```go
import security "github.com/Dorico-Dynamics/txova-go-security"

// OTP errors
security.OTPExpired()    // CodeOTPExpired
security.OTPInvalid()    // CodeOTPInvalid
security.OTPLocked()     // CodeOTPLocked
security.OTPCooldown()   // CodeOTPCooldown

// Encryption errors
security.EncryptionFailed(err)  // CodeEncryptionFailed
security.DecryptionFailed(err)  // CodeDecryptionFailed
security.InvalidKey("reason")   // CodeInvalidKey

// PIN errors
security.InvalidPIN("reason")   // CodeInvalidPIN
```

### Error Checking

```go
err := service.Verify(ctx, phone, code)

if security.IsOTPExpired(err) {
    // Handle expired OTP
}
if security.IsOTPInvalid(err) {
    // Handle invalid OTP
}
if security.IsOTPLocked(err) {
    // Handle lockout
}
if security.IsOTPCooldown(err) {
    // Handle cooldown
}
```

### HTTP Status Mapping

```go
status := security.HTTPStatus(err.Code())
// CodeOTPExpired       -> 401 Unauthorized
// CodeOTPInvalid       -> 401 Unauthorized
// CodeOTPLocked        -> 429 Too Many Requests
// CodeOTPCooldown      -> 429 Too Many Requests
// CodeEncryptionFailed -> 500 Internal Server Error
// CodeDecryptionFailed -> 400 Bad Request
// CodeInvalidKey       -> 500 Internal Server Error
// CodeInvalidPIN       -> 400 Bad Request
```
