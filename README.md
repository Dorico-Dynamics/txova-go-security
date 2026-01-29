# txova-go-security

Security library providing password hashing, OTP generation, encryption, PIN management, and PII handling for Txova services.

## Overview

`txova-go-security` implements all security-sensitive operations for Txova, including Argon2id password hashing, TOTP generation, AES-GCM encryption, and PII data masking for compliance.

**Module:** `github.com/txova/txova-go-security`

## Features

- **Password Hashing** - Argon2id with OWASP-recommended parameters
- **OTP Generation** - TOTP-based 6-digit codes with configurable validity
- **Encryption** - AES-256-GCM for sensitive data at rest
- **PIN Management** - Secure ride verification PIN generation
- **PII Masking** - Log-safe masking of sensitive data

## Packages

| Package | Description |
|---------|-------------|
| `password` | Argon2id password hashing and verification |
| `otp` | Time-based OTP generation and validation |
| `crypto` | AES-GCM encryption/decryption |
| `pin` | Secure ride PIN generation |
| `pii` | PII data masking utilities |

## Installation

```bash
go get github.com/txova/txova-go-security
```

## Usage

### Password Hashing

```go
import "github.com/txova/txova-go-security/password"

// Hash password with Argon2id
hash, err := password.Hash("user-password")
// Returns: $argon2id$v=19$m=65536,t=3,p=4$...

// Verify password
valid, err := password.Verify("user-password", hash)
```

### OTP Generation

```go
import "github.com/txova/txova-go-security/otp"

generator := otp.New(otp.Config{
    Digits:   6,
    Validity: 5 * time.Minute,
})

// Generate OTP for phone verification
code, expiresAt, err := generator.Generate("+258841234567")
// code: "847291"

// Verify OTP
valid, err := generator.Verify("+258841234567", "847291")
```

### Encryption

```go
import "github.com/txova/txova-go-security/crypto"

encryptor := crypto.New([]byte(encryptionKey))

// Encrypt sensitive data
encrypted, err := encryptor.Encrypt([]byte("sensitive-data"))

// Decrypt data
decrypted, err := encryptor.Decrypt(encrypted)
```

### Ride PIN

```go
import "github.com/txova/txova-go-security/pin"

// Generate secure 4-digit PIN (excludes sequential/repeated)
ridePin := pin.Generate()
// Returns: "7382" (never "1234" or "1111")

// Validate PIN format
valid := pin.Validate("7382")
```

### PII Masking

```go
import "github.com/txova/txova-go-security/pii"

// Mask phone number
masked := pii.MaskPhone("+258841234567")
// Returns: "+258841***567"

// Mask email
masked := pii.MaskEmail("user@example.com")
// Returns: "u***@example.com"

// Mask for logging
safeLog := pii.MaskStruct(user)
```

## Security Parameters

### Argon2id Configuration

| Parameter | Value |
|-----------|-------|
| Memory | 64 MB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt Length | 16 bytes |
| Key Length | 32 bytes |

### OTP Configuration

| Parameter | Value |
|-----------|-------|
| Digits | 6 |
| Algorithm | SHA-1 |
| Validity | 5 minutes |
| Max Attempts | 3 |

## Dependencies

**Internal:**
- `txova-go-types`
- `txova-go-core`

**External:**
- `golang.org/x/crypto` - Cryptographic primitives
- `github.com/pquerna/otp` - TOTP implementation

## Development

### Requirements

- Go 1.25+

### Testing

```bash
go test ./...
```

### Test Coverage Target

> 95%

## License

Proprietary - Dorico Dynamics
