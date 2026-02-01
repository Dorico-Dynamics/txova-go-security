package password

import "errors"

// Sentinel errors for password operations.
var (
	// ErrEmptyPassword is returned when an empty password is provided.
	ErrEmptyPassword = errors.New("password cannot be empty")

	// ErrInvalidHash is returned when the hash format is invalid.
	ErrInvalidHash = errors.New("invalid password hash format")

	// ErrIncompatibleVersion is returned when the hash uses an unsupported Argon2 version.
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
)
