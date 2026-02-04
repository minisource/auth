package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
)

// OTPService handles OTP operations
type OTPService struct {
	cfg             *config.OTPConfig
	otpRepo         repository.OTPRepository
	logger          logging.Logger
	notifierClient  NotifierClient // Interface for sending OTP via notifier
	settingsService *SettingsService
}

// SMSRequest holds parameters for template-based SMS
type SMSRequest struct {
	Phone    string
	Template string
	Data     map[string]string
}

// NotifierClient interface for sending notifications
type NotifierClient interface {
	SendSMS(ctx context.Context, phone, message string) error
	SendSMSWithData(ctx context.Context, req *SMSRequest) error
	SendEmail(ctx context.Context, email, subject, body string) error
}

func NewOTPService(cfg *config.OTPConfig, otpRepo repository.OTPRepository, logger logging.Logger, notifier NotifierClient, settingsService *SettingsService) *OTPService {
	return &OTPService{
		cfg:             cfg,
		otpRepo:         otpRepo,
		logger:          logger,
		notifierClient:  notifier,
		settingsService: settingsService,
	}
}

// GenerateAndSendOTP generates a new OTP and sends it via the appropriate channel
func (s *OTPService) GenerateAndSendOTP(ctx context.Context, userID uuid.UUID, target, otpType string) (*SendOTPResponse, error) {
	// Check if there's an existing valid OTP (rate limiting)
	existingOTP, err := s.otpRepo.GetByTarget(ctx, target, otpType)
	if err == nil && existingOTP != nil && !existingOTP.IsExpired() {
		// Calculate remaining time
		remainingTime := time.Until(existingOTP.ExpiresAt)
		s.logger.Warn(logging.General, logging.Api, "OTP request rate limited - existing OTP not expired", map[logging.ExtraKey]interface{}{
			"target":        target,
			"type":          otpType,
			"remainingTime": remainingTime.Seconds(),
		})
		// Return rate limit error with remaining time
		return nil, NewOTPStillValidError(int64(remainingTime.Seconds()))
	}

	// Get OTP settings from database
	otpLength := s.settingsService.GetOTPLength(ctx)
	otpExpiry := s.settingsService.GetOTPExpiry(ctx)

	// Generate OTP code
	code, err := GenerateOTPCode(otpLength)
	if err != nil {
		s.logger.Error(logging.General, logging.Api, "Failed to generate OTP", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	// Create OTP record in Redis
	expiresAt := time.Now().Add(otpExpiry)
	otp := &models.OTP{
		ID:        uuid.New(),
		UserID:    userID,
		Code:      code,
		Type:      otpType,
		Target:    target,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.otpRepo.Create(ctx, otp); err != nil {
		s.logger.Error(logging.Redis, logging.Insert, "Failed to create OTP", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	// Send OTP via appropriate channel
	if s.notifierClient != nil {
		if err := s.sendOTP(ctx, target, code, otpType); err != nil {
			s.logger.Error(logging.General, logging.ExternalService, "Failed to send OTP", map[logging.ExtraKey]interface{}{
				"error":  err.Error(),
				"target": target,
				"type":   otpType,
			})
			// Check if it's a notifier unavailable error
			if errors.Is(err, ErrNotifierUnavailable) {
				return nil, NewNotifierUnavailableError()
			}
			return nil, err
		}
	}

	s.logger.Info(logging.General, logging.Api, "OTP generated and sent", map[logging.ExtraKey]interface{}{
		"target": target,
		"type":   otpType,
	})

	return &SendOTPResponse{
		ExpiresAt: expiresAt,
		ExpiresIn: int64(time.Until(expiresAt).Seconds()),
	}, nil
}

func (s *OTPService) sendOTP(ctx context.Context, target, code, otpType string) error {
	s.logger.Info(logging.General, logging.ExternalService, "Sending OTP", map[logging.ExtraKey]interface{}{
		"target": target,
		"type":   otpType,
	})

	switch otpType {
	case models.OTPTypeEmailVerification, models.OTPTypePasswordReset:
		s.logger.Info(logging.General, logging.ExternalService, "Sending OTP via Email", map[logging.ExtraKey]interface{}{
			"target": target,
			"type":   otpType,
		})
		subject := s.getEmailSubject(otpType)
		message := s.formatOTPMessage(code, otpType)
		return s.notifierClient.SendEmail(ctx, target, subject, message)

	case models.OTPTypePhoneVerification, models.OTPTypeLogin:
		s.logger.Info(logging.General, logging.ExternalService, "Sending OTP via SMS", map[logging.ExtraKey]interface{}{
			"target": target,
			"type":   otpType,
		})
		// Use template-based SMS for OTP
		// Template "verify" is the predefined OTP verification template
		// The notifier service will look up the template and map "code" to provider-specific token
		return s.notifierClient.SendSMSWithData(ctx, &SMSRequest{
			Phone:    target,
			Template: "verify",
			Data:     map[string]string{"code": code},
		})

	default:
		// Try to detect target type
		if ValidateEmail(target) {
			s.logger.Info(logging.General, logging.ExternalService, "Detected email target, sending via Email", map[logging.ExtraKey]interface{}{
				"target": target,
			})
			message := s.formatOTPMessage(code, otpType)
			return s.notifierClient.SendEmail(ctx, target, "Verification Code", message)
		}
		s.logger.Info(logging.General, logging.ExternalService, "Detected phone target, sending via SMS", map[logging.ExtraKey]interface{}{
			"target": target,
		})
		// Use template-based SMS for OTP
		return s.notifierClient.SendSMSWithData(ctx, &SMSRequest{
			Phone:    target,
			Template: "verify",
			Data:     map[string]string{"code": code},
		})
	}
}

func (s *OTPService) formatOTPMessage(code, otpType string) string {
	switch otpType {
	case models.OTPTypeEmailVerification:
		return "Your email verification code is: " + code + ". This code expires in 5 minutes."
	case models.OTPTypePhoneVerification:
		return "Your phone verification code is: " + code
	case models.OTPTypePasswordReset:
		return "Your password reset code is: " + code + ". This code expires in 5 minutes."
	case models.OTPTypeLogin:
		return "Your login verification code is: " + code
	default:
		return "Your verification code is: " + code
	}
}

func (s *OTPService) getEmailSubject(otpType string) string {
	switch otpType {
	case models.OTPTypeEmailVerification:
		return "Verify Your Email Address"
	case models.OTPTypePasswordReset:
		return "Reset Your Password"
	default:
		return "Verification Code"
	}
}

// VerifyOTP verifies an OTP code
func (s *OTPService) VerifyOTP(ctx context.Context, target, code, otpType string) error {
	s.logger.Debug(logging.Redis, logging.Select, "Verifying OTP from Redis", map[logging.ExtraKey]interface{}{
		"target":  target,
		"code":    code,
		"otpType": otpType,
	})

	// Get from Redis
	otp, err := s.otpRepo.GetByTarget(ctx, target, otpType)
	if err != nil {
		s.logger.Error(logging.Redis, logging.Select, "Failed to get OTP from Redis", map[logging.ExtraKey]interface{}{
			"error":  err.Error(),
			"target": target,
			"type":   otpType,
		})
		return err
	}

	if otp == nil {
		s.logger.Warn(logging.Redis, logging.Select, "OTP not found in Redis", map[logging.ExtraKey]interface{}{
			"target": target,
			"type":   otpType,
		})
		return ErrOTPInvalid
	}

	s.logger.Debug(logging.Redis, logging.Select, "OTP found in Redis", map[logging.ExtraKey]interface{}{
		"storedCode":   otp.Code,
		"providedCode": code,
		"target":       otp.Target,
		"expiresAt":    otp.ExpiresAt,
		"isUsed":       otp.IsUsed,
		"attempts":     otp.Attempts,
	})

	// Check if expired
	if otp.IsExpired() {
		s.otpRepo.Delete(ctx, target, otpType)
		return ErrOTPExpired
	}

	// Check max attempts
	if otp.Attempts >= s.cfg.MaxAttempts {
		s.otpRepo.Delete(ctx, target, otpType)
		return ErrOTPMaxAttempts
	}

	// Verify code
	if otp.Code != code {
		// Increment attempts
		if err := s.otpRepo.IncrementAttempts(ctx, target, otpType); err != nil {
			s.logger.Debug(logging.Redis, logging.Update, "Failed to increment OTP attempts", map[logging.ExtraKey]interface{}{
				"error": err.Error(),
			})
		}
		return ErrOTPInvalid
	}

	// Mark as used and delete
	if err := s.otpRepo.MarkUsed(ctx, target, otpType); err != nil {
		s.logger.Error(logging.Redis, logging.Update, "Failed to mark OTP as used", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	// Delete from Redis after successful verification
	s.otpRepo.Delete(ctx, target, otpType)

	s.logger.Info(logging.General, logging.Api, "OTP verified successfully", map[logging.ExtraKey]interface{}{
		"target": target,
		"type":   otpType,
	})

	return nil
}
