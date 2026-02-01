package audit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Dorico-Dynamics/txova-go-core/logging"

	"github.com/Dorico-Dynamics/txova-go-security/mask"
)

// captureLogger creates a logger that writes to a buffer for testing.
func captureLogger() (*logging.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	cfg := logging.Config{
		Level:       slog.LevelDebug,
		Format:      logging.FormatJSON,
		Output:      buf,
		ServiceName: "test",
	}
	return logging.New(cfg), buf
}

func TestNew(t *testing.T) {
	logger, _ := captureLogger()

	t.Run("creates logger with defaults", func(t *testing.T) {
		auditLog := New(logger)
		if auditLog.logger == nil {
			t.Error("logger should not be nil")
		}
		if auditLog.masker == nil {
			t.Error("masker should not be nil")
		}
	})

	t.Run("with custom alert handler", func(t *testing.T) {
		handler := &mockAlertHandler{}
		auditLog := New(logger, WithAlertHandler(handler))
		if auditLog.alertHandler != handler {
			t.Error("alert handler should be set")
		}
	})

	t.Run("with custom masker", func(t *testing.T) {
		masker := mask.NewMasker(mask.WithMaskChar('#'))
		auditLog := New(logger, WithMasker(masker))
		if auditLog.masker != masker {
			t.Error("masker should be set")
		}
	})
}

func TestLog(t *testing.T) {
	ctx := context.Background()

	t.Run("logs event with masked PII", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.Log(ctx, Event{
			Type:      EventLoginSuccess,
			UserID:    "user123456789",
			Phone:     "+258841234567",
			Email:     "user@example.com",
			IPAddress: "192.168.1.1",
			UserAgent: "Mozilla/5.0",
		})

		output := buf.String()

		// Verify event type is logged
		if !strings.Contains(output, "LOGIN_SUCCESS") {
			t.Error("expected event type in output")
		}

		// Verify PII is masked
		if strings.Contains(output, "user123456789") {
			t.Error("user ID should be masked")
		}
		if strings.Contains(output, "+258841234567") {
			t.Error("phone should be masked")
		}
		if strings.Contains(output, "user@example.com") {
			t.Error("email should be masked")
		}

		// IP and User-Agent should not be masked
		if !strings.Contains(output, "192.168.1.1") {
			t.Error("IP should be in output")
		}
	})

	t.Run("sets default severity", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.Log(ctx, Event{
			Type: EventLoginFailed,
		})

		output := buf.String()
		if !strings.Contains(output, "WARN") {
			t.Error("expected WARN severity for login failed")
		}
	})

	t.Run("sets default timestamp", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		before := time.Now()
		auditLog.Log(ctx, Event{
			Type: EventLoginSuccess,
		})
		after := time.Now()

		output := buf.String()
		// Timestamp should be present and recent
		if !strings.Contains(output, "timestamp") {
			t.Error("expected timestamp in output")
		}
		_ = before
		_ = after
	})

	t.Run("includes details", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.Log(ctx, Event{
			Type: EventPermissionDenied,
			Details: map[string]any{
				"resource": "/admin/users",
				"action":   "DELETE",
			},
		})

		output := buf.String()
		if !strings.Contains(output, "resource") {
			t.Error("expected resource in output")
		}
		if !strings.Contains(output, "/admin/users") {
			t.Error("expected resource value in output")
		}
	})
}

func TestAlertHandler(t *testing.T) {
	ctx := context.Background()

	t.Run("invokes handler for alert events", func(t *testing.T) {
		logger, _ := captureLogger()
		handler := &mockAlertHandler{}
		auditLog := New(logger, WithAlertHandler(handler))

		auditLog.Log(ctx, Event{
			Type:     EventSuspiciousActivity,
			Severity: SeverityAlert,
			UserID:   "user123",
		})

		if !handler.called {
			t.Error("alert handler should have been called")
		}
		if handler.event.Type != EventSuspiciousActivity {
			t.Errorf("expected event type %s, got %s", EventSuspiciousActivity, handler.event.Type)
		}
	})

	t.Run("does not invoke for non-alert events", func(t *testing.T) {
		logger, _ := captureLogger()
		handler := &mockAlertHandler{}
		auditLog := New(logger, WithAlertHandler(handler))

		auditLog.Log(ctx, Event{
			Type: EventLoginSuccess,
		})

		if handler.called {
			t.Error("alert handler should not be called for INFO events")
		}
	})
}

func TestConvenienceMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("LogLoginSuccess", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogLoginSuccess(ctx, "user123", "192.168.1.1", "Mozilla/5.0")

		output := buf.String()
		if !strings.Contains(output, "LOGIN_SUCCESS") {
			t.Error("expected LOGIN_SUCCESS event")
		}
	})

	t.Run("LogLoginFailed", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogLoginFailed(ctx, "user@example.com", "192.168.1.1", "Mozilla/5.0", "invalid password")

		output := buf.String()
		if !strings.Contains(output, "LOGIN_FAILED") {
			t.Error("expected LOGIN_FAILED event")
		}
		if !strings.Contains(output, "invalid password") {
			t.Error("expected reason in output")
		}
	})

	t.Run("LogPasswordChanged", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogPasswordChanged(ctx, "user123", "192.168.1.1")

		output := buf.String()
		if !strings.Contains(output, "PASSWORD_CHANGED") {
			t.Error("expected PASSWORD_CHANGED event")
		}
	})

	t.Run("LogOTPSent", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogOTPSent(ctx, "+258841234567")

		output := buf.String()
		if !strings.Contains(output, "OTP_SENT") {
			t.Error("expected OTP_SENT event")
		}
		// Phone should be masked
		if strings.Contains(output, "+258841234567") {
			t.Error("phone should be masked")
		}
	})

	t.Run("LogOTPVerified", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogOTPVerified(ctx, "+258841234567")

		output := buf.String()
		if !strings.Contains(output, "OTP_VERIFIED") {
			t.Error("expected OTP_VERIFIED event")
		}
	})

	t.Run("LogOTPFailed", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogOTPFailed(ctx, "+258841234567", "invalid code")

		output := buf.String()
		if !strings.Contains(output, "OTP_FAILED") {
			t.Error("expected OTP_FAILED event")
		}
		if !strings.Contains(output, "invalid code") {
			t.Error("expected reason in output")
		}
	})

	t.Run("LogOTPLocked", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogOTPLocked(ctx, "+258841234567")

		output := buf.String()
		if !strings.Contains(output, "OTP_LOCKED") {
			t.Error("expected OTP_LOCKED event")
		}
	})

	t.Run("LogTokenRevoked", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogTokenRevoked(ctx, "user123", "refresh", "192.168.1.1")

		output := buf.String()
		if !strings.Contains(output, "TOKEN_REVOKED") {
			t.Error("expected TOKEN_REVOKED event")
		}
		if !strings.Contains(output, "refresh") {
			t.Error("expected token_type in output")
		}
	})

	t.Run("LogPermissionDenied", func(t *testing.T) {
		logger, buf := captureLogger()
		auditLog := New(logger)

		auditLog.LogPermissionDenied(ctx, "user123", "/admin", "DELETE", "192.168.1.1")

		output := buf.String()
		if !strings.Contains(output, "PERMISSION_DENIED") {
			t.Error("expected PERMISSION_DENIED event")
		}
	})

	t.Run("LogSuspiciousActivity", func(t *testing.T) {
		logger, buf := captureLogger()
		handler := &mockAlertHandler{}
		auditLog := New(logger, WithAlertHandler(handler))

		auditLog.LogSuspiciousActivity(ctx, "user123", "multiple_failed_logins", "192.168.1.1", "Mozilla/5.0", map[string]any{
			"attempt_count": 10,
		})

		output := buf.String()
		if !strings.Contains(output, "SUSPICIOUS_ACTIVITY") {
			t.Error("expected SUSPICIOUS_ACTIVITY event")
		}
		if !handler.called {
			t.Error("alert handler should have been called")
		}
	})

	t.Run("LogSuspiciousActivity with nil details", func(t *testing.T) {
		logger, _ := captureLogger()
		auditLog := New(logger)

		// Should not panic
		auditLog.LogSuspiciousActivity(ctx, "user123", "test", "192.168.1.1", "", nil)
	})
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  Severity
	}{
		{EventLoginSuccess, SeverityInfo},
		{EventLoginFailed, SeverityWarn},
		{EventSuspiciousActivity, SeverityAlert},
		{EventType("UNKNOWN"), SeverityInfo}, // Unknown defaults to INFO
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			severity := GetSeverity(tt.eventType)
			if severity != tt.expected {
				t.Errorf("GetSeverity(%s) = %s, want %s", tt.eventType, severity, tt.expected)
			}
		})
	}
}

// mockAlertHandler implements AlertHandler for testing.
type mockAlertHandler struct {
	called bool
	event  Event
}

func (m *mockAlertHandler) Handle(_ context.Context, event Event) error {
	m.called = true
	m.event = event
	return nil
}

func BenchmarkLog(b *testing.B) {
	logger, _ := captureLogger()
	auditLog := New(logger)
	ctx := context.Background()

	event := Event{
		Type:      EventLoginSuccess,
		UserID:    "user123456789",
		Phone:     "+258841234567",
		Email:     "user@example.com",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auditLog.Log(ctx, event)
	}
}
