package security

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		code       errors.Code
		wantStatus int
	}{
		{CodeOTPExpired, http.StatusUnauthorized},
		{CodeOTPInvalid, http.StatusUnauthorized},
		{CodeOTPLocked, http.StatusTooManyRequests},
		{CodeOTPCooldown, http.StatusTooManyRequests},
		{CodeEncryptionFailed, http.StatusInternalServerError},
		{CodeDecryptionFailed, http.StatusBadRequest},
		{CodeInvalidKey, http.StatusInternalServerError},
		{CodeInvalidPIN, http.StatusBadRequest},
		{"UNKNOWN_CODE", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			got := HTTPStatus(tt.code)
			if got != tt.wantStatus {
				t.Errorf("HTTPStatus(%q) = %d, want %d", tt.code, got, tt.wantStatus)
			}
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name        string
		err         *errors.AppError
		wantCode    errors.Code
		wantMessage string
	}{
		{
			name:        "OTPExpired",
			err:         OTPExpired(),
			wantCode:    CodeOTPExpired,
			wantMessage: "OTP has expired",
		},
		{
			name:        "OTPInvalid",
			err:         OTPInvalid(),
			wantCode:    CodeOTPInvalid,
			wantMessage: "invalid OTP",
		},
		{
			name:        "OTPLocked",
			err:         OTPLocked(),
			wantCode:    CodeOTPLocked,
			wantMessage: "account temporarily locked due to too many failed attempts",
		},
		{
			name:        "OTPCooldown",
			err:         OTPCooldown(),
			wantCode:    CodeOTPCooldown,
			wantMessage: "please wait before requesting a new OTP",
		},
		{
			name:        "InvalidKey",
			err:         InvalidKey("key must be 32 bytes"),
			wantCode:    CodeInvalidKey,
			wantMessage: "key must be 32 bytes",
		},
		{
			name:        "InvalidPIN",
			err:         InvalidPIN("PIN cannot be sequential"),
			wantCode:    CodeInvalidPIN,
			wantMessage: "PIN cannot be sequential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code() != tt.wantCode {
				t.Errorf("Code() = %q, want %q", tt.err.Code(), tt.wantCode)
			}
			if tt.err.Message() != tt.wantMessage {
				t.Errorf("Message() = %q, want %q", tt.err.Message(), tt.wantMessage)
			}
		})
	}
}

func TestWrappedErrors(t *testing.T) {
	cause := fmt.Errorf("underlying crypto error")

	t.Run("EncryptionFailed", func(t *testing.T) {
		err := EncryptionFailed(cause)
		if err.Code() != CodeEncryptionFailed {
			t.Errorf("Code() = %q, want %q", err.Code(), CodeEncryptionFailed)
		}
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("DecryptionFailed", func(t *testing.T) {
		err := DecryptionFailed(cause)
		if err.Code() != CodeDecryptionFailed {
			t.Errorf("Code() = %q, want %q", err.Code(), CodeDecryptionFailed)
		}
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrorCheckers(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		checker func(error) bool
		want    bool
	}{
		{"IsOTPExpired with OTPExpired", OTPExpired(), IsOTPExpired, true},
		{"IsOTPExpired with OTPInvalid", OTPInvalid(), IsOTPExpired, false},
		{"IsOTPInvalid with OTPInvalid", OTPInvalid(), IsOTPInvalid, true},
		{"IsOTPInvalid with OTPExpired", OTPExpired(), IsOTPInvalid, false},
		{"IsOTPLocked with OTPLocked", OTPLocked(), IsOTPLocked, true},
		{"IsOTPLocked with OTPCooldown", OTPCooldown(), IsOTPLocked, false},
		{"IsOTPCooldown with OTPCooldown", OTPCooldown(), IsOTPCooldown, true},
		{"IsOTPCooldown with OTPLocked", OTPLocked(), IsOTPCooldown, false},
		{"IsEncryptionFailed with EncryptionFailed", EncryptionFailed(nil), IsEncryptionFailed, true},
		{"IsEncryptionFailed with DecryptionFailed", DecryptionFailed(nil), IsEncryptionFailed, false},
		{"IsDecryptionFailed with DecryptionFailed", DecryptionFailed(nil), IsDecryptionFailed, true},
		{"IsDecryptionFailed with EncryptionFailed", EncryptionFailed(nil), IsDecryptionFailed, false},
		{"IsInvalidKey with InvalidKey", InvalidKey("test"), IsInvalidKey, true},
		{"IsInvalidKey with InvalidPIN", InvalidPIN("test"), IsInvalidKey, false},
		{"IsInvalidPIN with InvalidPIN", InvalidPIN("test"), IsInvalidPIN, true},
		{"IsInvalidPIN with InvalidKey", InvalidKey("test"), IsInvalidPIN, false},
		{"IsOTPExpired with nil", nil, IsOTPExpired, false},
		{"IsOTPExpired with plain error", fmt.Errorf("plain error"), IsOTPExpired, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.checker(tt.err)
			if got != tt.want {
				t.Errorf("checker(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestErrorInterface(t *testing.T) {
	err := OTPExpired()

	// Test error interface
	if err.Error() == "" {
		t.Error("Error() returned empty string")
	}

	// Test that it contains the code and message
	errStr := err.Error()
	if errStr != "OTP_EXPIRED: OTP has expired" {
		t.Errorf("Error() = %q, want %q", errStr, "OTP_EXPIRED: OTP has expired")
	}
}

func TestWrappedErrorString(t *testing.T) {
	cause := fmt.Errorf("cipher error")
	err := EncryptionFailed(cause)

	errStr := err.Error()
	expected := "ENCRYPTION_FAILED: encryption failed: cipher error"
	if errStr != expected {
		t.Errorf("Error() = %q, want %q", errStr, expected)
	}
}
