package service

import (
	"context"
	"fmt"
	"time"

	"github.com/minisource/auth/config"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-sdk/auth"
	notifier "github.com/minisource/go-sdk/notifier"
)

var (
	ErrNotifierUnavailable = fmt.Errorf("notification service is temporarily unavailable")
)

// GRPCNotifierClient implements NotifierClient using gRPC connection to notifier service
type GRPCNotifierClient struct {
	client     *notifier.Client
	authClient *auth.Client
	logger     logging.Logger
}

// NewGRPCNotifierClient creates a new gRPC-based notifier client
func NewGRPCNotifierClient(cfg *config.NotifierConfig, authCfg *config.Config, logger logging.Logger) (*GRPCNotifierClient, error) {
	if !cfg.Enabled {
		logger.Info(logging.General, logging.Startup, "Notifier client disabled", nil)
		return nil, nil
	}

	// Create auth client for service-to-service authentication if credentials are provided
	var authClient *auth.Client
	if cfg.ClientID != "" && cfg.ClientSecret != "" {
		// Use auth service URL from config (self-auth for getting service token)
		authBaseURL := fmt.Sprintf("http://localhost:%s", authCfg.Server.Port)
		authClient = auth.NewClient(auth.ClientConfig{
			BaseURL:      authBaseURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Timeout:      10 * time.Second,
			AutoRefresh:  true,
			Logger:       logger,
		})
		logger.Info(logging.General, logging.Startup, "Auth client for notifier created", map[logging.ExtraKey]interface{}{
			"clientID": cfg.ClientID,
		})
	}

	client, err := notifier.NewClient(context.Background(), notifier.Config{
		Address:    cfg.GRPCAddress,
		Timeout:    30 * time.Second,
		AuthClient: authClient,
		Logger:     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create notifier client: %w", err)
	}

	logger.Info(logging.General, logging.Startup, "Notifier client connected with retry and logging", map[logging.ExtraKey]interface{}{
		"address":     cfg.GRPCAddress,
		"authEnabled": authClient != nil,
		"retries":     "3 attempts with exponential backoff",
	})

	return &GRPCNotifierClient{
		client:     client,
		authClient: authClient,
		logger:     logger,
	}, nil
}

// SendSMS sends an SMS message (retry logic now handled by SDK)
func (c *GRPCNotifierClient) SendSMS(ctx context.Context, phone, message string) error {
	if c.client == nil {
		c.logger.Warn(logging.General, logging.Api, "Notifier client not initialized", map[logging.ExtraKey]interface{}{
			"phone": phone,
		})
		return ErrNotifierUnavailable
	}

	_, err := c.client.SendSMS(ctx, "", phone, message)
	if err != nil {
		c.logger.Error(logging.General, logging.Api, "Failed to send SMS via notifier gRPC", map[logging.ExtraKey]interface{}{
			"phone":         phone,
			"error":         err.Error(),
			"errorType":     fmt.Sprintf("%T", err),
			"grpcAddress":   c.client,
			"hasAuthClient": c.authClient != nil,
		})
		// Return the actual error with more context
		return fmt.Errorf("notifier gRPC call failed: %w (check if notifier gRPC server is running on port 9003)", err)
	}

	c.logger.Info(logging.General, logging.Api, "SMS sent successfully", map[logging.ExtraKey]interface{}{
		"phone": phone,
	})
	return nil
}

// SendSMSWithData sends an SMS using template key and data dictionary
// The notifier service handles provider-specific logic (template lookup, token mapping)
func (c *GRPCNotifierClient) SendSMSWithData(ctx context.Context, req *SMSRequest) error {
	if c.client == nil {
		c.logger.Warn(logging.General, logging.Api, "Notifier client not initialized", map[logging.ExtraKey]interface{}{
			"phone":    req.Phone,
			"template": req.Template,
		})
		return ErrNotifierUnavailable
	}

	_, err := c.client.SendSMSWithData(ctx, &notifier.SMSRequest{
		Phone:    req.Phone,
		Template: req.Template,
		Data:     req.Data,
	})
	if err != nil {
		c.logger.Error(logging.General, logging.Api, "Failed to send SMS via notifier gRPC", map[logging.ExtraKey]interface{}{
			"phone":    req.Phone,
			"template": req.Template,
			"error":    err.Error(),
		})
		return fmt.Errorf("notifier gRPC call failed: %w", err)
	}

	c.logger.Info(logging.General, logging.Api, "SMS sent successfully", map[logging.ExtraKey]interface{}{
		"phone":    req.Phone,
		"template": req.Template,
	})
	return nil
}

// SendEmail sends an email message (retry logic now handled by SDK)
func (c *GRPCNotifierClient) SendEmail(ctx context.Context, email, subject, body string) error {
	if c.client == nil {
		c.logger.Warn(logging.General, logging.Api, "Notifier client not initialized", map[logging.ExtraKey]interface{}{
			"email": email,
		})
		return ErrNotifierUnavailable
	}

	_, err := c.client.SendEmail(ctx, "", email, subject, body)
	if err != nil {
		c.logger.Error(logging.General, logging.Api, "Failed to send email", map[logging.ExtraKey]interface{}{
			"email": email,
			"error": err.Error(),
		})
		// Check if it's a service unavailable error from the SDK
		return ErrNotifierUnavailable
	}

	c.logger.Info(logging.General, logging.Api, "Email sent successfully", map[logging.ExtraKey]interface{}{
		"email":   email,
		"subject": subject,
	})
	return nil
}

// Close closes the gRPC connection
func (c *GRPCNotifierClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// HTTPNotifierClient implements NotifierClient using HTTP calls to notifier service
// This is an alternative to gRPC for environments where gRPC is not available
type HTTPNotifierClient struct {
	baseURL string
	logger  logging.Logger
	enabled bool
}

// NewHTTPNotifierClient creates a new HTTP-based notifier client
func NewHTTPNotifierClient(cfg *config.NotifierConfig, logger logging.Logger) *HTTPNotifierClient {
	return &HTTPNotifierClient{
		baseURL: cfg.HTTPURL,
		logger:  logger,
		enabled: cfg.Enabled,
	}
}

// SendSMS sends an SMS message via HTTP
func (c *HTTPNotifierClient) SendSMS(ctx context.Context, phone, message string) error {
	if !c.enabled {
		c.logger.Warn(logging.General, logging.Api, "Notifier client disabled, skipping SMS", map[logging.ExtraKey]interface{}{
			"phone": phone,
		})
		return nil
	}

	// TODO: Implement HTTP client for SMS
	// For now, log and return nil (non-blocking)
	c.logger.Info(logging.General, logging.Api, "SMS would be sent (HTTP client)", map[logging.ExtraKey]interface{}{
		"phone":   phone,
		"message": message,
	})
	return nil
}

// SendSMSWithData sends SMS using template key and data dictionary via HTTP
func (c *HTTPNotifierClient) SendSMSWithData(ctx context.Context, req *SMSRequest) error {
	if !c.enabled {
		c.logger.Warn(logging.General, logging.Api, "Notifier client disabled, skipping SMS", map[logging.ExtraKey]interface{}{
			"phone":    req.Phone,
			"template": req.Template,
		})
		return nil
	}

	// TODO: Implement HTTP client for SMS
	c.logger.Info(logging.General, logging.Api, "SMS would be sent (HTTP client)", map[logging.ExtraKey]interface{}{
		"phone":    req.Phone,
		"template": req.Template,
		"data":     req.Data,
	})
	return nil
}

// SendEmail sends an email message via HTTP
func (c *HTTPNotifierClient) SendEmail(ctx context.Context, email, subject, body string) error {
	if !c.enabled {
		c.logger.Warn(logging.General, logging.Api, "Notifier client disabled, skipping email", map[logging.ExtraKey]interface{}{
			"email": email,
		})
		return nil
	}

	// TODO: Implement HTTP client for email
	// For now, log and return nil (non-blocking)
	c.logger.Info(logging.General, logging.Api, "Email would be sent (HTTP client)", map[logging.ExtraKey]interface{}{
		"email":   email,
		"subject": subject,
	})
	return nil
}

// Close is a no-op for HTTP client
func (c *HTTPNotifierClient) Close() error {
	return nil
}

// NoopNotifierClient is a no-op implementation for when notifier is disabled
type NoopNotifierClient struct {
	logger logging.Logger
}

// NewNoopNotifierClient creates a no-op notifier client
func NewNoopNotifierClient(logger logging.Logger) *NoopNotifierClient {
	return &NoopNotifierClient{logger: logger}
}

// SendSMS logs but doesn't send
func (c *NoopNotifierClient) SendSMS(ctx context.Context, phone, message string) error {
	c.logger.Info(logging.General, logging.Api, "Notifier disabled - SMS not sent", map[logging.ExtraKey]interface{}{
		"phone":   phone,
		"message": message,
	})
	return nil
}

// SendSMSWithData logs but doesn't send
func (c *NoopNotifierClient) SendSMSWithData(ctx context.Context, req *SMSRequest) error {
	c.logger.Info(logging.General, logging.Api, "Notifier disabled - SMS not sent", map[logging.ExtraKey]interface{}{
		"phone":    req.Phone,
		"template": req.Template,
		"data":     req.Data,
	})
	return nil
}

// SendEmail logs but doesn't send
func (c *NoopNotifierClient) SendEmail(ctx context.Context, email, subject, body string) error {
	c.logger.Info(logging.General, logging.Api, "Notifier disabled - Email not sent", map[logging.ExtraKey]interface{}{
		"email":   email,
		"subject": subject,
	})
	return nil
}

// Close is a no-op
func (c *NoopNotifierClient) Close() error {
	return nil
}
