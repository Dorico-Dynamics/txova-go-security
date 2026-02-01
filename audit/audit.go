// Package audit provides security event logging with automatic PII masking.
// It wraps txova-go-core/logging with security-specific event types and severity levels.
package audit

import (
	"context"
	"time"

	"github.com/Dorico-Dynamics/txova-go-core/logging"

	"github.com/Dorico-Dynamics/txova-go-security/mask"
)

// EventType represents the type of security event.
type EventType string

// Security event types.
const (
	EventLoginSuccess       EventType = "LOGIN_SUCCESS"
	EventLoginFailed        EventType = "LOGIN_FAILED"
	EventPasswordChanged    EventType = "PASSWORD_CHANGED"
	EventOTPSent            EventType = "OTP_SENT"
	EventOTPVerified        EventType = "OTP_VERIFIED"
	EventOTPFailed          EventType = "OTP_FAILED"
	EventOTPLocked          EventType = "OTP_LOCKED"
	EventTokenRevoked       EventType = "TOKEN_REVOKED"
	EventPermissionDenied   EventType = "PERMISSION_DENIED"
	EventSuspiciousActivity EventType = "SUSPICIOUS_ACTIVITY"
)

// Severity represents the severity level of a security event.
type Severity string

// Severity levels.
const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityAlert Severity = "ALERT"
)

// defaultSeverity maps event types to their default severity.
var defaultSeverity = map[EventType]Severity{
	EventLoginSuccess:       SeverityInfo,
	EventLoginFailed:        SeverityWarn,
	EventPasswordChanged:    SeverityInfo,
	EventOTPSent:            SeverityInfo,
	EventOTPVerified:        SeverityInfo,
	EventOTPFailed:          SeverityWarn,
	EventOTPLocked:          SeverityWarn,
	EventTokenRevoked:       SeverityInfo,
	EventPermissionDenied:   SeverityWarn,
	EventSuspiciousActivity: SeverityAlert,
}

// Event represents a security audit event.
type Event struct {
	Type      EventType
	Severity  Severity
	UserID    string
	Phone     string
	Email     string
	IPAddress string
	UserAgent string
	Timestamp time.Time
	Details   map[string]any
}

// AlertHandler is called for events with ALERT severity.
type AlertHandler interface {
	Handle(ctx context.Context, event Event) error
}

// noopAlertHandler is the default no-op handler.
type noopAlertHandler struct{}

func (noopAlertHandler) Handle(_ context.Context, _ Event) error {
	return nil
}

// Logger provides security audit logging with automatic PII masking.
type Logger struct {
	logger       *logging.Logger
	alertHandler AlertHandler
	masker       *mask.Masker
}

// Option is a functional option for configuring the Logger.
type Option func(*Logger)

// WithAlertHandler sets the handler for ALERT severity events.
func WithAlertHandler(handler AlertHandler) Option {
	return func(l *Logger) {
		if handler != nil {
			l.alertHandler = handler
		}
	}
}

// WithMasker sets a custom masker for PII fields.
func WithMasker(masker *mask.Masker) Option {
	return func(l *Logger) {
		if masker != nil {
			l.masker = masker
		}
	}
}

// New creates a new audit Logger.
func New(logger *logging.Logger, opts ...Option) *Logger {
	l := &Logger{
		logger:       logger,
		alertHandler: noopAlertHandler{},
		masker:       mask.NewMasker(),
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// Log logs a security event with automatic PII masking.
func (l *Logger) Log(ctx context.Context, event Event) {
	// Set defaults
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.Severity == "" {
		event.Severity = defaultSeverity[event.Type]
		if event.Severity == "" {
			event.Severity = SeverityInfo
		}
	}

	// Build log attributes with masked PII
	attrs := []any{
		"event_type", string(event.Type),
		"severity", string(event.Severity),
		"timestamp", event.Timestamp.Format(time.RFC3339),
	}

	if event.UserID != "" {
		attrs = append(attrs, "user_id", l.masker.ID(event.UserID))
	}
	if event.Phone != "" {
		attrs = append(attrs, "phone", l.masker.Phone(event.Phone))
	}
	if event.Email != "" {
		attrs = append(attrs, "email", l.masker.Email(event.Email))
	}
	if event.IPAddress != "" {
		attrs = append(attrs, "ip_address", event.IPAddress)
	}
	if event.UserAgent != "" {
		attrs = append(attrs, "user_agent", event.UserAgent)
	}

	// Add details
	for k, v := range event.Details {
		attrs = append(attrs, k, v)
	}

	// Log at appropriate level
	msg := "Security event: " + string(event.Type)
	switch event.Severity {
	case SeverityAlert:
		l.logger.ErrorContext(ctx, msg, attrs...)
		// Invoke alert handler (errors are logged but not propagated)
		if err := l.alertHandler.Handle(ctx, event); err != nil {
			l.logger.ErrorContext(ctx, "Alert handler failed", "error", err.Error())
		}
	case SeverityWarn:
		l.logger.WarnContext(ctx, msg, attrs...)
	default:
		l.logger.InfoContext(ctx, msg, attrs...)
	}
}

// Convenience methods for common events.

// LogLoginSuccess logs a successful login.
func (l *Logger) LogLoginSuccess(ctx context.Context, userID, ip, userAgent string) {
	l.Log(ctx, Event{
		Type:      EventLoginSuccess,
		UserID:    userID,
		IPAddress: ip,
		UserAgent: userAgent,
	})
}

// LogLoginFailed logs a failed login attempt.
func (l *Logger) LogLoginFailed(ctx context.Context, identifier, ip, userAgent, reason string) {
	l.Log(ctx, Event{
		Type:      EventLoginFailed,
		Email:     identifier, // Could be email or phone
		IPAddress: ip,
		UserAgent: userAgent,
		Details:   map[string]any{"reason": reason},
	})
}

// LogPasswordChanged logs a password change.
func (l *Logger) LogPasswordChanged(ctx context.Context, userID, ip string) {
	l.Log(ctx, Event{
		Type:      EventPasswordChanged,
		UserID:    userID,
		IPAddress: ip,
	})
}

// LogOTPSent logs OTP generation and sending.
func (l *Logger) LogOTPSent(ctx context.Context, phone string) {
	l.Log(ctx, Event{
		Type:  EventOTPSent,
		Phone: phone,
	})
}

// LogOTPVerified logs successful OTP verification.
func (l *Logger) LogOTPVerified(ctx context.Context, phone string) {
	l.Log(ctx, Event{
		Type:  EventOTPVerified,
		Phone: phone,
	})
}

// LogOTPFailed logs failed OTP verification.
func (l *Logger) LogOTPFailed(ctx context.Context, phone, reason string) {
	l.Log(ctx, Event{
		Type:    EventOTPFailed,
		Phone:   phone,
		Details: map[string]any{"reason": reason},
	})
}

// LogOTPLocked logs account lockout due to OTP failures.
func (l *Logger) LogOTPLocked(ctx context.Context, phone string) {
	l.Log(ctx, Event{
		Type:  EventOTPLocked,
		Phone: phone,
	})
}

// LogTokenRevoked logs token revocation.
func (l *Logger) LogTokenRevoked(ctx context.Context, userID, tokenType, ip string) {
	l.Log(ctx, Event{
		Type:      EventTokenRevoked,
		UserID:    userID,
		IPAddress: ip,
		Details:   map[string]any{"token_type": tokenType},
	})
}

// LogPermissionDenied logs an access denial.
func (l *Logger) LogPermissionDenied(ctx context.Context, userID, resource, action, ip string) {
	l.Log(ctx, Event{
		Type:      EventPermissionDenied,
		UserID:    userID,
		IPAddress: ip,
		Details: map[string]any{
			"resource": resource,
			"action":   action,
		},
	})
}

// LogSuspiciousActivity logs suspicious activity that requires alert.
func (l *Logger) LogSuspiciousActivity(ctx context.Context, userID, activity, ip, userAgent string, details map[string]any) {
	event := Event{
		Type:      EventSuspiciousActivity,
		Severity:  SeverityAlert,
		UserID:    userID,
		IPAddress: ip,
		UserAgent: userAgent,
		Details:   details,
	}
	if event.Details == nil {
		event.Details = make(map[string]any)
	}
	event.Details["activity"] = activity

	l.Log(ctx, event)
}

// GetSeverity returns the default severity for an event type.
func GetSeverity(eventType EventType) Severity {
	if severity, ok := defaultSeverity[eventType]; ok {
		return severity
	}
	return SeverityInfo
}
