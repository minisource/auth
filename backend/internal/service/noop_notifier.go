package service

import (
	"context"
	"fmt"

	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-sdk/notifier"
)

var ErrNotifierUnavailable = fmt.Errorf("notification service is temporarily unavailable")

// NoopNotifierClient is a no-op implementation for when notifier is disabled
type NoopNotifierClient struct {
	logger logging.Logger
}

// NewNoopNotifierClient creates a no-op notifier client
func NewNoopNotifierClient(logger logging.Logger) *NoopNotifierClient {
	return &NoopNotifierClient{logger: logger}
}

// SendSMS reports that sending is unavailable (no real provider configured)
func (c *NoopNotifierClient) SendSMS(ctx context.Context, userID, phone, body string) (string, error) {
	c.logger.Warn(logging.General, logging.Api, "Notifier disabled - SMS not sent", map[logging.ExtraKey]interface{}{
		"userId": userID,
		"phone":  phone,
	})
	return "", ErrNotifierUnavailable
}

// SendSMSWithData reports that sending is unavailable (no real provider configured)
func (c *NoopNotifierClient) SendSMSWithData(ctx context.Context, req *notifier.SMSRequest) (string, error) {
	c.logger.Warn(logging.General, logging.Api, "Notifier disabled - SMS template not sent", map[logging.ExtraKey]interface{}{
		"phone":    req.Phone,
		"template": req.Template,
	})
	return "", ErrNotifierUnavailable
}

// SendEmail reports that sending is unavailable (no real provider configured)
func (c *NoopNotifierClient) SendEmail(ctx context.Context, userID, email, subject, body string) (string, error) {
	c.logger.Warn(logging.General, logging.Api, "Notifier disabled - Email not sent", map[logging.ExtraKey]interface{}{
		"userId":  userID,
		"email":   email,
		"subject": subject,
	})
	return "", ErrNotifierUnavailable
}

// Close is a no-op
func (c *NoopNotifierClient) Close() error {
	return nil
}
