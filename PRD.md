# txova-go-security

## Overview
Security utilities library providing password hashing, OTP generation, encryption, token generation, and PII masking for protecting sensitive data.

**Module:** `github.com/txova/txova-go-security`

---

## Packages

### `password` - Password Hashing

**Algorithm:** Argon2id (winner of Password Hashing Competition)

**Parameters:**
| Parameter | Value | Description |
|-----------|-------|-------------|
| Memory | 64 MB | Memory usage |
| Iterations | 3 | Time cost |
| Parallelism | 4 | Threads |
| Salt length | 16 bytes | Random salt |
| Hash length | 32 bytes | Output length |

**Functions:**
| Function | Description |
|----------|-------------|
| Hash(password) | Generate hash from password |
| Verify(password, hash) | Compare password to hash |
| NeedsRehash(hash) | Check if params outdated |

**Requirements:**
- Never store plaintext passwords
- Use crypto/rand for salt generation
- Constant-time comparison to prevent timing attacks
- Support parameter upgrades without breaking existing hashes

---

### `otp` - One-Time Password

**Configuration:**
| Setting | Value | Description |
|---------|-------|-------------|
| Length | 6 digits | OTP length |
| Expiry | 5 minutes | Time to live |
| Max attempts | 3 | Before lockout |
| Lockout duration | 15 minutes | After max attempts |
| Cooldown | 60 seconds | Between requests |

**Functions:**
| Function | Description |
|----------|-------------|
| Generate(phone) | Create and store OTP |
| Verify(phone, code) | Validate OTP |
| Invalidate(phone) | Clear OTP |
| GetAttempts(phone) | Check attempt count |
| IsLocked(phone) | Check lockout status |

**Storage (Redis):**
| Key Pattern | TTL | Description |
|-------------|-----|-------------|
| otp:{phone} | 5m | The OTP code |
| otp:attempts:{phone} | 15m | Attempt counter |
| otp:lockout:{phone} | 15m | Lockout flag |
| otp:cooldown:{phone} | 60s | Rate limit |

**Requirements:**
- Use crypto/rand for OTP generation
- Hash OTP before storing (don't store plaintext)
- Increment attempts on verification (success or fail)
- Clear OTP after successful verification
- Return generic error (don't reveal if phone exists)

---

### `token` - Secure Token Generation

**Token Types:**
| Type | Length | Use Case |
|------|--------|----------|
| Session token | 32 bytes | User sessions |
| Refresh token | 32 bytes | JWT refresh |
| Reset token | 32 bytes | Password reset |
| Verification token | 32 bytes | Email verification |
| API key | 32 bytes | Service auth |

**Functions:**
| Function | Description |
|----------|-------------|
| Generate() | Create random token (hex encoded) |
| GenerateURLSafe() | Create URL-safe token (base64) |
| Hash(token) | SHA256 hash for storage |

**Requirements:**
- Use crypto/rand exclusively
- Never store plaintext tokens (store hash)
- Tokens must be constant-time compared
- URL-safe tokens for links

---

### `pin` - Ride PIN Generation

**Rules:**
| Rule | Description |
|------|-------------|
| Length | 4 digits |
| No sequential | Not 1234, 2345, etc. |
| No reverse sequential | Not 4321, 5432, etc. |
| No repeated | Not 1111, 2222, etc. |
| No common | Not 0000, 1234, etc. |

**Blacklisted PINs:**
0000, 1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 9999,
1234, 2345, 3456, 4567, 5678, 6789, 4321, 3210, 0123

**Functions:**
| Function | Description |
|----------|-------------|
| Generate() | Create valid ride PIN |
| Validate(pin) | Check PIN meets rules |

**Requirements:**
- Use crypto/rand
- Retry if generated PIN fails rules
- Max 10 retries before error

---

### `encrypt` - Data Encryption

**Algorithm:** AES-256-GCM (Authenticated Encryption)

**Key Management:**
| Aspect | Requirement |
|--------|-------------|
| Key length | 256 bits (32 bytes) |
| Key source | Environment variable or secrets manager |
| Key rotation | Support multiple keys with key ID |
| Nonce | 12 bytes, unique per encryption |

**Functions:**
| Function | Description |
|----------|-------------|
| Encrypt(plaintext) | Encrypt and return ciphertext |
| Decrypt(ciphertext) | Decrypt and return plaintext |
| EncryptField(value) | Encrypt for database storage |
| DecryptField(value) | Decrypt from database |

**Ciphertext Format:**
`{key_id}:{nonce_base64}:{ciphertext_base64}`

**Requirements:**
- Use unique nonce for every encryption
- Include key ID for rotation support
- Never reuse nonce with same key
- Support decryption with old keys during rotation

---

### `mask` - PII Masking

**Masking Rules:**
| Data Type | Input | Output |
|-----------|-------|--------|
| Phone | +258841234567 | +258****4567 |
| Email | user@example.com | u***@example.com |
| Name | John Smith | J*** S**** |
| Card | 4111111111111111 | ****1111 |
| ID | AB123456 | AB***456 |

**Functions:**
| Function | Description |
|----------|-------------|
| MaskPhone(phone) | Mask phone number |
| MaskEmail(email) | Mask email address |
| MaskName(name) | Mask personal name |
| MaskCard(number) | Mask card number |
| MaskID(id) | Mask ID document |
| MaskAuto(value, type) | Auto-detect and mask |

**Requirements:**
- Preserve enough for identification (last 4 digits)
- Log only masked values
- Use in error messages returned to clients
- Configurable mask character (default: *)

---

### `audit` - Security Audit Logging

**Events to Log:**
| Event | Severity | Description |
|-------|----------|-------------|
| LOGIN_SUCCESS | INFO | Successful login |
| LOGIN_FAILED | WARN | Failed login attempt |
| PASSWORD_CHANGED | INFO | Password update |
| OTP_SENT | INFO | OTP generated |
| OTP_VERIFIED | INFO | OTP validated |
| OTP_FAILED | WARN | Invalid OTP attempt |
| OTP_LOCKED | WARN | Account locked |
| TOKEN_REVOKED | INFO | Session terminated |
| PERMISSION_DENIED | WARN | Access denied |
| SUSPICIOUS_ACTIVITY | ALERT | Potential attack |

**Log Fields:**
| Field | Description |
|-------|-------------|
| event_type | Event identifier |
| severity | INFO, WARN, ALERT |
| user_id | Affected user (masked) |
| ip_address | Request source |
| user_agent | Client info |
| timestamp | Event time |
| details | Event-specific data |

**Requirements:**
- Never log sensitive data (passwords, tokens, OTPs)
- Always log IP and user agent
- Structured JSON format
- Send ALERT events to monitoring

---

## Dependencies

**Internal:**
- `txova-go-types`
- `txova-go-core`

**External:**
- `golang.org/x/crypto/argon2` — Password hashing

---

## Success Metrics
| Metric | Target |
|--------|--------|
| Test coverage | > 90% |
| Password hash time | 200-500ms |
| Encryption latency | < 1ms |
| OTP verification rate | > 95% |
| Zero plaintext leaks | Required |
