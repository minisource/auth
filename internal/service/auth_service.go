package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
)

// AuthService handles user authentication
type AuthService struct {
	cfg              *config.Config
	userRepo         repository.UserRepository
	sessionRepo      repository.SessionRepository
	refreshTokenRepo repository.RefreshTokenRepository
	roleRepo         repository.RoleRepository
	loginLogRepo     repository.LoginLogRepository
	tokenService     *TokenService
	passwordService  *PasswordService
	otpService       *OTPService
	settingsService  *SettingsService
	logger           logging.Logger
}

func NewAuthService(
	cfg *config.Config,
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	roleRepo repository.RoleRepository,
	loginLogRepo repository.LoginLogRepository,
	tokenService *TokenService,
	passwordService *PasswordService,
	otpService *OTPService,
	settingsService *SettingsService,
	logger logging.Logger,
) *AuthService {
	return &AuthService{
		cfg:              cfg,
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		roleRepo:         roleRepo,
		loginLogRepo:     loginLogRepo,
		tokenService:     tokenService,
		passwordService:  passwordService,
		otpService:       otpService,
		settingsService:  settingsService,
		logger:           logger,
	}
}

// LoginRequest represents login request data
type LoginRequest struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
}

// AuthResponse represents authentication response
type AuthResponse struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	TokenType    string    `json:"tokenType"`
	User         *UserInfo `json:"user"`
}

type UserInfo struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	Username      string   `json:"username"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	Phone         string   `json:"phone,omitempty"`
	Avatar        string   `json:"avatar,omitempty"`
	EmailVerified bool     `json:"emailVerified"`
	PhoneVerified bool     `json:"phoneVerified"`
	Roles         []string `json:"roles"`
}

// Login authenticates a user with email and password
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	email := NormalizeEmail(req.Email)

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error(logging.Postgres, logging.Select, "Failed to get user", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	if user == nil {
		s.logLoginAttempt(ctx, uuid.Nil, uuid.Nil, models.LoginActionLoginFailed, req.IPAddress, req.UserAgent, false, "user not found")
		return nil, ErrInvalidCredentials
	}

	// Check if user is active
	if !user.IsActive {
		s.logLoginAttempt(ctx, user.ID, uuid.Nil, models.LoginActionLoginFailed, req.IPAddress, req.UserAgent, false, "user disabled")
		return nil, ErrUserDisabled
	}

	// Check if user is locked
	if user.IsLocked() {
		s.logLoginAttempt(ctx, user.ID, uuid.Nil, models.LoginActionLoginFailed, req.IPAddress, req.UserAgent, false, "user locked")
		return nil, ErrUserLocked
	}

	// Verify password
	if !s.passwordService.VerifyPassword(req.Password, user.PasswordHash) {
		s.handleFailedLogin(ctx, user, req.IPAddress, req.UserAgent)
		return nil, ErrInvalidCredentials
	}

	// Reset failed attempts on successful login
	if user.FailedAttempts > 0 {
		s.userRepo.ResetFailedAttempts(ctx, user.ID)
	}

	// Create session and tokens
	return s.createAuthSession(ctx, user, req.IPAddress, req.UserAgent)
}

// RegisterRequest represents registration request
type RegisterRequest struct {
	Email     string
	Password  string
	Username  string
	FirstName string
	LastName  string
	Phone     string
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*models.User, error) {
	// Check if registration is allowed
	if !s.settingsService.IsRegistrationAllowed(ctx) {
		return nil, ErrRegistrationDisabled
	}

	email := NormalizeEmail(req.Email)
	phone := NormalizePhone(req.Phone)

	// Check if email exists
	exists, _ := s.userRepo.ExistsByEmail(ctx, email)
	if exists {
		return nil, ErrEmailExists
	}

	// Check if phone exists (if provided)
	if phone != "" {
		exists, _ := s.userRepo.ExistsByPhone(ctx, phone)
		if exists {
			return nil, ErrPhoneExists
		}
	}

	// Check if username exists
	if req.Username != "" {
		exists, _ := s.userRepo.ExistsByUsername(ctx, req.Username)
		if exists {
			return nil, ErrUsernameExists
		}
	}

	// Validate password
	if err := s.passwordService.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	passwordHash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	// Generate username if not provided
	username := req.Username
	if username == "" {
		username = generateUsernameFromEmail(email)
	}

	// Create user
	user := &models.User{
		Email:        email,
		Phone:        phone,
		Username:     username,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsActive:     true,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error(logging.Postgres, logging.Insert, "Failed to create user", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	// Assign default role
	defaultRole, err := s.roleRepo.GetByName(ctx, models.RoleUser)
	if err == nil && defaultRole != nil {
		s.userRepo.AssignRole(ctx, user.ID, defaultRole.ID)
	}

	s.logger.Info(logging.General, logging.Api, "User registered", map[logging.ExtraKey]interface{}{
		"userId": user.ID,
		"email":  email,
	})

	return user, nil
}

// SendOTPRequest represents OTP send request
type SendOTPRequest struct {
	Phone     string
	Email     string
	Type      string // "login", "email_verification", "phone_verification", "password_reset"
	FirstName string // For auto-registration
	LastName  string
}

type SendOTPResponse struct {
	ExpiresAt time.Time `json:"expiresAt"`
	ExpiresIn int64     `json:"expiresIn"` // Seconds remaining until expiration
}

// SendOTP sends OTP and auto-registers user if phone doesn't exist
func (s *AuthService) SendOTP(ctx context.Context, req *SendOTPRequest) (*SendOTPResponse, error) {
	target := ""
	var userID uuid.UUID

	if req.Phone != "" {
		phone := NormalizePhone(req.Phone)
		target = phone

		// Check if user exists
		user, err := s.userRepo.GetByPhone(ctx, phone)
		if err != nil {
			return nil, err
		}

		if user == nil {
			// Auto-register user with phone
			user, err = s.autoRegisterByPhone(ctx, phone, req.FirstName, req.LastName)
			if err != nil {
				return nil, err
			}
		}
		userID = user.ID
	} else if req.Email != "" {
		email := NormalizeEmail(req.Email)
		target = email

		user, err := s.userRepo.GetByEmail(ctx, email)
		if err != nil {
			return nil, err
		}

		if user == nil {
			return nil, ErrUserNotFound
		}
		userID = user.ID
	} else {
		return nil, ErrUserNotFound
	}

	// Generate and send OTP
	return s.otpService.GenerateAndSendOTP(ctx, userID, target, req.Type)
}

// autoRegisterByPhone creates a new user with just a phone number
func (s *AuthService) autoRegisterByPhone(ctx context.Context, phone, firstName, lastName string) (*models.User, error) {
	if !s.settingsService.IsRegistrationAllowed(ctx) {
		return nil, ErrRegistrationDisabled
	}

	// Generate a temporary password (user will set it later or use OTP login)
	tempPassword, _ := GenerateSecureToken(16)
	passwordHash, _ := s.passwordService.HashPassword(tempPassword)

	// Generate username from phone
	username := "user_" + phone[len(phone)-4:]

	user := &models.User{
		Phone:        phone,
		Username:     username,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
		IsActive:     true,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		// Handle unique constraint - might need to append random suffix
		username = username + "_" + uuid.New().String()[:4]
		user.Username = username
		if err := s.userRepo.Create(ctx, user); err != nil {
			return nil, err
		}
	}

	// Assign default role
	defaultRole, _ := s.roleRepo.GetByName(ctx, models.RoleUser)
	if defaultRole != nil {
		s.userRepo.AssignRole(ctx, user.ID, defaultRole.ID)
	}

	s.logger.Info(logging.General, logging.Api, "User auto-registered by phone", map[logging.ExtraKey]interface{}{
		"userId": user.ID,
		"phone":  phone,
	})

	return user, nil
}

// VerifyOTPAndLogin verifies OTP and creates session
func (s *AuthService) VerifyOTPAndLogin(ctx context.Context, target, code, otpType, ipAddress, userAgent string) (*AuthResponse, error) {
	originalTarget := target
	// Normalize target (phone or email) to match format used when sending OTP
	if ValidateEmail(target) {
		target = NormalizeEmail(target)
	} else {
		target = NormalizePhone(target)
	}

	s.logger.Debug(logging.Validation, logging.Api, "Verifying OTP with normalized target", map[logging.ExtraKey]interface{}{
		"originalTarget":   originalTarget,
		"normalizedTarget": target,
		"code":             code,
		"type":             otpType,
	})

	// Verify OTP
	if err := s.otpService.VerifyOTP(ctx, target, code, otpType); err != nil {
		return nil, err
	}

	// Get user
	var user *models.User
	var err error

	if ValidateEmail(target) {
		user, err = s.userRepo.GetByEmail(ctx, target)
	} else {
		user, err = s.userRepo.GetByPhone(ctx, target)
	}

	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	// Mark as verified
	if ValidateEmail(target) && !user.EmailVerified {
		user.EmailVerified = true
		s.userRepo.Update(ctx, user)
	} else if !user.PhoneVerified {
		user.PhoneVerified = true
		s.userRepo.Update(ctx, user)
	}

	// Create session
	return s.createAuthSession(ctx, user, ipAddress, userAgent)
}

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Validate refresh token
	claims, err := s.tokenService.ValidateToken(refreshToken)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}

	if claims.TokenType != "refresh" {
		return nil, ErrRefreshTokenInvalid
	}

	// Get refresh token from DB
	storedToken, err := s.refreshTokenRepo.GetByToken(ctx, refreshToken)
	if err != nil || storedToken == nil || !storedToken.IsValid() {
		return nil, ErrRefreshTokenInvalid
	}

	// Get user
	userID, _ := uuid.Parse(claims.UserID)
	user, err := s.userRepo.GetWithRoles(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if !user.IsActive {
		return nil, ErrUserDisabled
	}

	// Revoke old refresh token
	s.refreshTokenRepo.Revoke(ctx, storedToken.Token)

	// Create new session
	sessionID, _ := uuid.Parse(claims.SessionID)
	return s.createTokensForSession(ctx, user, sessionID)
}

// Logout revokes session and tokens
func (s *AuthService) Logout(ctx context.Context, accessToken string, revokeAll bool) error {
	claims, err := s.tokenService.ValidateToken(accessToken)
	if err != nil {
		return nil // Already invalid, consider logged out
	}

	userID, _ := uuid.Parse(claims.UserID)
	sessionID, _ := uuid.Parse(claims.SessionID)

	if revokeAll {
		// Revoke all sessions for user
		s.sessionRepo.RevokeAllByUserID(ctx, userID)
		s.refreshTokenRepo.RevokeByUserID(ctx, userID)
	} else {
		// Revoke current session only
		s.sessionRepo.Revoke(ctx, sessionID)
		s.sessionRepo.InvalidateCachedSession(ctx, sessionID.String())
	}

	s.logLoginAttempt(ctx, userID, sessionID, models.LoginActionLogout, "", "", true, "")

	return nil
}

// Helper methods

func (s *AuthService) createAuthSession(ctx context.Context, user *models.User, ipAddress, userAgent string) (*AuthResponse, error) {
	// Create session
	session := &models.Session{
		UserID:       user.ID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		IsActive:     true,
		ExpiresAt:    time.Now().Add(s.cfg.JWT.RefreshExpiry),
		LastActiveAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = ipAddress
	s.userRepo.Update(ctx, user)

	// Log successful login
	s.logLoginAttempt(ctx, user.ID, session.ID, models.LoginActionLogin, ipAddress, userAgent, true, "")

	return s.createTokensForSession(ctx, user, session.ID)
}

func (s *AuthService) createTokensForSession(ctx context.Context, user *models.User, sessionID uuid.UUID) (*AuthResponse, error) {
	// Get user with roles
	userWithRoles, err := s.userRepo.GetWithRoles(ctx, user.ID)
	if err != nil {
		userWithRoles = user
	}

	roles := extractRoleNames(userWithRoles.Roles)
	permissions := extractPermissions(userWithRoles.Roles)

	// Get tenant ID from user (can be nil for system-level users)
	var tenantID *uuid.UUID = user.TenantID

	// Generate access token with tenant context
	accessToken, err := s.tokenService.GenerateAccessToken(user, tenantID, roles, permissions, sessionID)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, expiresAt, err := s.tokenService.GenerateRefreshToken(user.ID, sessionID)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	rt := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		SessionID: sessionID,
		ExpiresAt: expiresAt,
	}
	s.refreshTokenRepo.Create(ctx, rt)

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.cfg.JWT.AccessExpiry),
		TokenType:    "Bearer",
		User: &UserInfo{
			ID:            user.ID.String(),
			Email:         user.Email,
			Username:      user.Username,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Phone:         user.Phone,
			Avatar:        user.Avatar,
			EmailVerified: user.EmailVerified,
			PhoneVerified: user.PhoneVerified,
			Roles:         roles,
		},
	}, nil
}

func (s *AuthService) handleFailedLogin(ctx context.Context, user *models.User, ipAddress, userAgent string) {
	s.userRepo.IncrementFailedAttempts(ctx, user.ID)
	user.FailedAttempts++

	maxAttempts := s.settingsService.GetMaxLoginAttempts(ctx)
	if user.FailedAttempts >= maxAttempts {
		lockDuration := s.settingsService.GetLockDuration(ctx)
		lockedUntil := time.Now().Add(lockDuration)
		s.userRepo.LockUser(ctx, user.ID, &lockedUntil)

		s.logLoginAttempt(ctx, user.ID, uuid.Nil, models.LoginActionAccountLocked, ipAddress, userAgent, false, "max attempts exceeded")
	} else {
		s.logLoginAttempt(ctx, user.ID, uuid.Nil, models.LoginActionLoginFailed, ipAddress, userAgent, false, "invalid password")
	}
}

func (s *AuthService) logLoginAttempt(ctx context.Context, userID, sessionID uuid.UUID, action, ipAddress, userAgent string, success bool, errorMsg string) {
	log := &models.LoginLog{
		UserID:    userID,
		SessionID: sessionID,
		Action:    action,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   success,
		ErrorMsg:  errorMsg,
	}
	s.loginLogRepo.Create(ctx, log)
}

func extractRoleNames(roles []models.Role) []string {
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names
}

func extractPermissions(roles []models.Role) []string {
	permMap := make(map[string]bool)
	for _, role := range roles {
		for _, perm := range role.Permissions {
			permMap[perm.Name] = true
		}
	}
	perms := make([]string, 0, len(permMap))
	for p := range permMap {
		perms = append(perms, p)
	}
	return perms
}

func generateUsernameFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return "user_" + uuid.New().String()[:8]
}

// ResetPassword verifies OTP and updates user password
func (s *AuthService) ResetPassword(ctx context.Context, target, code, newPassword string) error {
	// Verify OTP for password reset
	if err := s.otpService.VerifyOTP(ctx, target, code, "password_reset"); err != nil {
		return err
	}

	// Get user
	var user *models.User
	var err error

	if ValidateEmail(target) {
		user, err = s.userRepo.GetByEmail(ctx, NormalizeEmail(target))
	} else {
		user, err = s.userRepo.GetByPhone(ctx, target)
	}

	if err != nil || user == nil {
		return ErrUserNotFound
	}

	// Hash new password
	passwordHash, err := s.passwordService.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password
	user.PasswordHash = passwordHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	// Revoke all sessions for security
	s.sessionRepo.RevokeAllByUserID(ctx, user.ID)
	s.refreshTokenRepo.RevokeByUserID(ctx, user.ID)

	s.logger.Info(logging.General, logging.Api, "Password reset successfully", map[logging.ExtraKey]interface{}{
		"userId": user.ID,
	})

	return nil
}

// VerifyEmailOrPhone verifies OTP and marks email/phone as verified
func (s *AuthService) VerifyEmailOrPhone(ctx context.Context, target, code, otpType string) error {
	// Verify OTP
	if err := s.otpService.VerifyOTP(ctx, target, code, otpType); err != nil {
		return err
	}

	// Get user
	var user *models.User
	var err error

	if ValidateEmail(target) {
		user, err = s.userRepo.GetByEmail(ctx, NormalizeEmail(target))
	} else {
		user, err = s.userRepo.GetByPhone(ctx, target)
	}

	if err != nil || user == nil {
		return ErrUserNotFound
	}

	// Mark as verified based on type
	if otpType == "email_verification" && !user.EmailVerified {
		user.EmailVerified = true
		s.logger.Info(logging.General, logging.Api, "Email verified", map[logging.ExtraKey]interface{}{
			"userId": user.ID,
			"email":  user.Email,
		})
	} else if otpType == "phone_verification" && !user.PhoneVerified {
		user.PhoneVerified = true
		s.logger.Info(logging.General, logging.Api, "Phone verified", map[logging.ExtraKey]interface{}{
			"userId": user.ID,
			"phone":  user.Phone,
		})
	}

	return s.userRepo.Update(ctx, user)
}
