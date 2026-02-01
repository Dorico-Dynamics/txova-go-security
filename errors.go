// Package security provides security utilities for the Txova platform.
package security

import (
	"net/http"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

// Security-specific error codes extending txova-go-core/errors.
const (
	// CodeOTPExpired indicates the OTP has expired.
	CodeOTPExpired errors.Code = "OTP_EXPIRED"
	// CodeOTPInvalid indicates the OTP is invalid.
	CodeOTPInvalid errors.Code = "OTP_INVALID"
	// CodeOTPLocked indicates the account is locked due to too many failed attempts.
	CodeOTPLocked errors.Code = "OTP_LOCKED"
	// CodeOTPCooldown indicates the user must wait before requesting a new OTP.
	CodeOTPCooldown errors.Code = "OTP_COOLDOWN"
	// CodeEncryptionFailed indicates an encryption operation failed.
	CodeEncryptionFailed errors.Code = "ENCRYPTION_FAILED"
	// CodeDecryptionFailed indicates a decryption operation failed.
	CodeDecryptionFailed errors.Code = "DECRYPTION_FAILED"
	// CodeInvalidKey indicates an invalid encryption key.
	CodeInvalidKey errors.Code = "INVALID_KEY"
	// CodeInvalidPIN indicates an invalid PIN format or value.
	CodeInvalidPIN errors.Code = "INVALID_PIN"
)

// codeHTTPStatus maps security error codes to HTTP status codes.
var codeHTTPStatus = map[errors.Code]int{
	CodeOTPExpired:       http.StatusUnauthorized,
	CodeOTPInvalid:       http.StatusUnauthorized,
	CodeOTPLocked:        http.StatusTooManyRequests,
	CodeOTPCooldown:      http.StatusTooManyRequests,
	CodeEncryptionFailed: http.StatusInternalServerError,
	CodeDecryptionFailed: http.StatusBadRequest,
	CodeInvalidKey:       http.StatusInternalServerError,
	CodeInvalidPIN:       http.StatusBadRequest,
}

// HTTPStatus returns the HTTP status code for the given security error code.
// Returns 500 if the code is not a known security code.
func HTTPStatus(code errors.Code) int {
	if status, ok := codeHTTPStatus[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// Error constructors for security-specific errors.

// OTPExpired creates an error indicating the OTP has expired.
func OTPExpired() *errors.AppError {
	return errors.New(CodeOTPExpired, "OTP has expired")
}

// OTPInvalid creates an error indicating the OTP is invalid.
func OTPInvalid() *errors.AppError {
	return errors.New(CodeOTPInvalid, "invalid OTP")
}

// OTPLocked creates an error indicating the account is locked.
func OTPLocked() *errors.AppError {
	return errors.New(CodeOTPLocked, "account temporarily locked due to too many failed attempts")
}

// OTPCooldown creates an error indicating the user must wait.
func OTPCooldown() *errors.AppError {
	return errors.New(CodeOTPCooldown, "please wait before requesting a new OTP")
}

// EncryptionFailed creates an error indicating encryption failed.
// The cause is wrapped but not exposed to clients.
func EncryptionFailed(cause error) *errors.AppError {
	return errors.Wrap(CodeEncryptionFailed, "encryption failed", cause)
}

// DecryptionFailed creates an error indicating decryption failed.
// The cause is wrapped but not exposed to clients.
func DecryptionFailed(cause error) *errors.AppError {
	return errors.Wrap(CodeDecryptionFailed, "decryption failed", cause)
}

// InvalidKey creates an error indicating an invalid encryption key.
func InvalidKey(message string) *errors.AppError {
	return errors.New(CodeInvalidKey, message)
}

// InvalidPIN creates an error indicating an invalid PIN.
func InvalidPIN(message string) *errors.AppError {
	return errors.New(CodeInvalidPIN, message)
}

// Error checking helpers.

// IsOTPExpired checks if the error is an OTP expired error.
func IsOTPExpired(err error) bool {
	return errors.IsCode(err, CodeOTPExpired)
}

// IsOTPInvalid checks if the error is an OTP invalid error.
func IsOTPInvalid(err error) bool {
	return errors.IsCode(err, CodeOTPInvalid)
}

// IsOTPLocked checks if the error is an OTP locked error.
func IsOTPLocked(err error) bool {
	return errors.IsCode(err, CodeOTPLocked)
}

// IsOTPCooldown checks if the error is an OTP cooldown error.
func IsOTPCooldown(err error) bool {
	return errors.IsCode(err, CodeOTPCooldown)
}

// IsEncryptionFailed checks if the error is an encryption failed error.
func IsEncryptionFailed(err error) bool {
	return errors.IsCode(err, CodeEncryptionFailed)
}

// IsDecryptionFailed checks if the error is a decryption failed error.
func IsDecryptionFailed(err error) bool {
	return errors.IsCode(err, CodeDecryptionFailed)
}

// IsInvalidKey checks if the error is an invalid key error.
func IsInvalidKey(err error) bool {
	return errors.IsCode(err, CodeInvalidKey)
}

// IsInvalidPIN checks if the error is an invalid PIN error.
func IsInvalidPIN(err error) bool {
	return errors.IsCode(err, CodeInvalidPIN)
}
