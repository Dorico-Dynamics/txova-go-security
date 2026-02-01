# txova-go-security

Security utilities library for the Txova platform providing password hashing, token generation, encryption, OTP services, PII masking, and audit logging.

## Installation

```bash
go get github.com/Dorico-Dynamics/txova-go-security
```

## Features

| Package | Description |
|---------|-------------|
| `password` | Argon2id password hashing with PHC string format |
| `token` | Cryptographically secure token generation |
| `pin` | Secure 4-digit PIN generation with validation |
| `encrypt` | AES-256-GCM encryption with key rotation |
| `mask` | PII masking for phone, email, name, card, ID |
| `otp` | Redis-backed OTP with rate limiting and lockout |
| `audit` | Security event logging with automatic PII masking |

## Quick Start

### Password Hashing

```go
import "github.com/Dorico-Dynamics/txova-go-security/password"

hasher := password.NewDefault()

// Hash a password
hash, err := hasher.Hash(ctx, "user-password")

// Verify a password
valid, err := hasher.Verify(ctx, "user-password", hash)

// Check if rehash is needed (parameter upgrade)
needsRehash, err := hasher.NeedsRehash(hash)
```

### Token Generation

```go
import "github.com/Dorico-Dynamics/txova-go-security/token"

// Generate session token (32 bytes, hex encoded)
sessionToken, err := token.GenerateSessionToken()

// Generate URL-safe token
urlToken, err := token.GenerateURLSafe()

// Hash token for storage
hashedToken := token.Hash(sessionToken)

// Compare token with stored hash
valid := token.Compare(sessionToken, hashedToken)
```

### PIN Generation

```go
import "github.com/Dorico-Dynamics/txova-go-security/pin"

// Generate secure 4-digit PIN
code, err := pin.Generate()

// Validate PIN format and rules
err := pin.Validate(code)
```

### Encryption

```go
import "github.com/Dorico-Dynamics/txova-go-security/encrypt"

// Create cipher with primary key
key, _ := encrypt.GenerateKey()
cipher, err := encrypt.New("key-v1", key)

// Encrypt data
ciphertext, err := cipher.Encrypt([]byte("sensitive data"))

// Decrypt data
plaintext, err := cipher.Decrypt(ciphertext)

// Key rotation
newKey, _ := encrypt.GenerateKey()
cipher.AddKey("key-v2", newKey)
cipher.SetPrimaryKey("key-v2")
```

### PII Masking

```go
import "github.com/Dorico-Dynamics/txova-go-security/mask"

// Mask various PII types
phone := mask.Phone("+258841234567")  // +2588****4567
email := mask.Email("user@example.com")  // u***@example.com
name := mask.Name("John Smith")  // J*** S****
card := mask.Card("4111111111111111")  // ************1111
id := mask.ID("AB1234567")  // AB****567
```

### OTP Service

```go
import "github.com/Dorico-Dynamics/txova-go-security/otp"

// Create service with Redis client
service := otp.New(redisClient,
    otp.WithExpiry(5*time.Minute),
    otp.WithMaxAttempts(3),
)

// Generate OTP
code, expiry, err := service.Generate(ctx, phone)

// Verify OTP
err := service.Verify(ctx, phone, code)

// Check lockout status
locked, err := service.IsLocked(ctx, phone)
```

### Audit Logging

```go
import "github.com/Dorico-Dynamics/txova-go-security/audit"

// Create audit logger
auditLog := audit.New(logger)

// Log security events
auditLog.LogLoginSuccess(ctx, userID, ip, userAgent)
auditLog.LogOTPSent(ctx, phone)
auditLog.LogSuspiciousActivity(ctx, userID, "multiple_failed_logins", ip, userAgent, nil)
```

## Dependencies

### Internal
- `github.com/Dorico-Dynamics/txova-go-core` - Errors and logging
- `github.com/Dorico-Dynamics/txova-go-types` - Contact types (PhoneNumber, Email)

### External
- `golang.org/x/crypto` - Argon2id implementation

## Test Coverage

| Package | Coverage |
|---------|----------|
| `errors` | 100% |
| `audit` | 96.3% |
| `mask` | 98.1% |
| `password` | 96.5% |
| `token` | 93.6% |
| `pin` | 92.6% |
| `encrypt` | 92.3% |
| `otp` | 83.8% |

## Security Considerations

1. **Password Hashing**: Uses Argon2id with OWASP-recommended parameters
2. **Token Generation**: Uses `crypto/rand` exclusively, never `math/rand`
3. **Encryption**: AES-256-GCM with unique nonces and key rotation support
4. **OTP Storage**: OTPs are SHA256-hashed before storage, never stored in plaintext
5. **PII Protection**: All PII is automatically masked in audit logs

## License

Proprietary - Dorico Dynamics
