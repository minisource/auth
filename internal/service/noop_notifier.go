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

// SendSMS logs but doesn't send
func (c *NoopNotifierClient) SendSMS(ctx context.Context, userID, phone, body string) (string, error) {
	c.logger.Info(logging.General, logging.Api, "Notifier disabled - SMS not sent", map[logging.ExtraKey]interface{}{
		"userId":  userID,
		"phone":   phone,
		"message": body,
	})
	return "noop-sms-id", nil
}

// SendSMSWithData logs but doesn't send
func (c *NoopNotifierClient) SendSMSWithData(ctx context.Context, req *notifier.SMSRequest) (string, error) {
	c.logger.Info(logging.General, logging.Api, "Notifier disabled - SMS template not sent", map[logging.ExtraKey]interface{}{
		"phone":    req.Phone,
		"template": req.Template,
		"data":     req.Data,
	})
	return "noop-sms-template-id", nil
}

// SendEmail logs but doesn't send
func (c *NoopNotifierClient) SendEmail(ctx context.Context, userID, email, subject, body string) (string, error) {
	c.logger.Info(logging.General, logging.Api, "Notifier disabled - Email not sent", map[logging.ExtraKey]interface{}{
		"userId":  userID,
		"email":   email,
		"subject": subject,
	})
	return "noop-email-id", nil
}

// Close is a no-op
func (c *NoopNotifierClient) Close() error {
	return nil
}
