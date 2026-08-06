package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
)

// UserService handles user management
type UserService struct {
	cfg              *config.Config
	userRepo         repository.UserRepository
	roleRepo         repository.RoleRepository
	sessionRepo      repository.SessionRepository
	refreshTokenRepo repository.RefreshTokenRepository
	loginLogRepo     repository.LoginLogRepository
	passwordService  *PasswordService
	logger           logging.Logger
}

func NewUserService(
	cfg *config.Config,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	sessionRepo repository.SessionRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	loginLogRepo repository.LoginLogRepository,
	passwordService *PasswordService,
	logger logging.Logger,
) *UserService {
	return &UserService{
		cfg:              cfg,
		userRepo:         userRepo,
		roleRepo:         roleRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		loginLogRepo:     loginLogRepo,
		passwordService:  passwordService,
		logger:           logger,
	}
}

// ─── Two-Factor Authentication (TOTP) ───────────────────────

type TwoFactorStatus struct {
	Enabled         bool   `json:"enabled"`
	Secret          string `json:"secret,omitempty"`
	ProvisioningURI string `json:"provisioningUri,omitempty"`
}

// GetTwoFactorStatus reports the current 2FA state. If a secret exists but 2FA
// is not yet enabled, it also returns the secret + provisioning URI so the
// client can resume setup.
func (s *UserService) GetTwoFactorStatus(ctx context.Context, userID uuid.UUID) (*TwoFactorStatus, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	status := &TwoFactorStatus{Enabled: user.TwoFactorEnabled}
	if !user.TwoFactorEnabled && user.TwoFactorSecret != "" {
		status.Secret = user.TwoFactorSecret
		status.ProvisioningURI = TOTPProvisioningURI(user.TwoFactorSecret, user.Email)
	}
	return status, nil
}

// SetupTwoFactor generates and persists a fresh TOTP secret (unless 2FA is already enabled).
func (s *UserService) SetupTwoFactor(ctx context.Context, userID uuid.UUID) (*TwoFactorStatus, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	if user.TwoFactorEnabled {
		return &TwoFactorStatus{Enabled: true}, nil
	}
	if user.TwoFactorSecret == "" {
		secret, err := GenerateTOTPSecret()
		if err != nil {
			return nil, err
		}
		user.TwoFactorSecret = secret
		if err := s.userRepo.Update(ctx, user); err != nil {
			return nil, err
		}
	}
	return &TwoFactorStatus{
		Enabled:         false,
		Secret:          user.TwoFactorSecret,
		ProvisioningURI: TOTPProvisioningURI(user.TwoFactorSecret, user.Email),
	}, nil
}

// EnableTwoFactor verifies the current TOTP code and activates 2FA.
func (s *UserService) EnableTwoFactor(ctx context.Context, userID uuid.UUID, code string) (*TwoFactorStatus, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	if user.TwoFactorEnabled {
		return &TwoFactorStatus{Enabled: true}, nil
	}
	if user.TwoFactorSecret == "" {
		return nil, NewTwoFactorNotSetupError()
	}
	if !ValidateTOTPCode(user.TwoFactorSecret, code) {
		return nil, NewTwoFactorInvalidError()
	}

	user.TwoFactorEnabled = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}
	return &TwoFactorStatus{Enabled: true}, nil
}

// DisableTwoFactor verifies the current TOTP code and deactivates 2FA.
func (s *UserService) DisableTwoFactor(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if !user.TwoFactorEnabled {
		return nil // idempotent
	}
	if !ValidateTOTPCode(user.TwoFactorSecret, code) {
		return NewTwoFactorInvalidError()
	}

	user.TwoFactorEnabled = false
	user.TwoFactorSecret = ""
	return s.userRepo.Update(ctx, user)
}

// SecurityEvent is a sanitized login/security audit entry for the current user.
type SecurityEvent struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Success   bool   `json:"success"`
	ErrorMsg  string `json:"errorMsg,omitempty"`
	IPAddress string `json:"ipAddress,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// GetSecurityEvents returns the latest security events for the user.
func (s *UserService) GetSecurityEvents(ctx context.Context, userID uuid.UUID, limit int) ([]SecurityEvent, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	logs, err := s.loginLogRepo.GetByUserID(ctx, userID, limit)
	if err != nil {
		return nil, err
	}
	result := make([]SecurityEvent, 0, len(logs))
	for _, l := range logs {
		result = append(result, SecurityEvent{
			ID:        l.ID.String(),
			Action:    l.Action,
			Success:   l.Success,
			ErrorMsg:  l.ErrorMsg,
			IPAddress: l.IPAddress,
			UserAgent: l.UserAgent,
			CreatedAt: l.CreatedAt.Format(time.RFC3339),
		})
	}
	return result, nil
}

// GetProfile returns user profile
func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetWithRoles(ctx, userID)
}

// UpdateProfileRequest represents profile update request
type UpdateProfileRequest struct {
	FirstName string
	LastName  string
	Avatar    string
	Birthday  *string
}

// UpdateProfile updates user profile
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, req *UpdateProfileRequest) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	user.FirstName = req.FirstName
	user.LastName = req.LastName
	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}
	if req.Birthday != nil {
		user.Birthday = req.Birthday
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return s.userRepo.GetWithRoles(ctx, userID)
}

// ChangePasswordRequest represents password change request
type ChangePasswordRequest struct {
	OldPassword string
	NewPassword string
}

// ChangePassword changes user password
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, req *ChangePasswordRequest) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrUserNotFound
	}

	// Verify old password
	if !s.passwordService.VerifyPassword(req.OldPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Validate new password
	if err := s.passwordService.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	hash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = hash

	// Remove hasDefaultPassword from metadata if present
	var metadata map[string]interface{}
	if user.Metadata == "" {
		user.Metadata = "{}"
	}
	if err := json.Unmarshal([]byte(user.Metadata), &metadata); err == nil {
		delete(metadata, "hasDefaultPassword")
		if updatedMetadata, err := json.Marshal(metadata); err == nil {
			user.Metadata = string(updatedMetadata)
		}
	}

	return s.userRepo.Update(ctx, user)
}

// SetPasswordRequest for setting password (for OTP-only users)
type SetPasswordRequest struct {
	Password string
}

// SetPassword sets password for users who don't have one
func (s *UserService) SetPassword(ctx context.Context, userID uuid.UUID, req *SetPasswordRequest) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrUserNotFound
	}

	// Validate password
	if err := s.passwordService.ValidatePassword(req.Password); err != nil {
		return err
	}

	// Hash password
	hash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return err
	}

	user.PasswordHash = hash

	// Remove hasDefaultPassword from metadata if present
	var metadata map[string]interface{}
	if user.Metadata == "" {
		user.Metadata = "{}"
	}
	if err := json.Unmarshal([]byte(user.Metadata), &metadata); err == nil {
		delete(metadata, "hasDefaultPassword")
		if updatedMetadata, err := json.Marshal(metadata); err == nil {
			user.Metadata = string(updatedMetadata)
		}
	}

	return s.userRepo.Update(ctx, user)
}

// GetUserByID returns user by ID (admin)
func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetWithRoles(ctx, userID)
}

// ListUsersRequest represents user list request
type ListUsersRequest struct {
	TenantID *uuid.UUID
	Page     int
	PageSize int
	Search   string
	RoleID   uuid.UUID
	IsActive *bool
}

// PaginationMeta holds pagination metadata
type PaginationMeta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"pageSize"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"totalPages"`
}

// ListUsersResponse represents user list response
type ListUsersResponse struct {
	Data []models.User  `json:"data"`
	Meta PaginationMeta `json:"meta"`
}

// ListUsers returns paginated user list (admin)
func (s *UserService) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 100 {
		req.PageSize = 20
	}

	offset := (req.Page - 1) * req.PageSize

	users, total, err := s.userRepo.ListWithFilters(ctx, req.TenantID, req.Search, req.RoleID, req.IsActive, offset, req.PageSize)
	if err != nil {
		return nil, err
	}

	totalPages := int(total) / req.PageSize
	if int(total)%req.PageSize > 0 {
		totalPages++
	}

	return &ListUsersResponse{
		Data: users,
		Meta: PaginationMeta{
			Page:       req.Page,
			PageSize:   req.PageSize,
			Total:      total,
			TotalPages: totalPages,
		},
	}, nil
}

// CreateUserRequest represents admin user creation request
type CreateUserRequest struct {
	Email     string
	Password  string
	Username  string
	FirstName string
	LastName  string
	Phone     string
	RoleIDs   []uuid.UUID
	IsActive  bool
}

// CreateUser creates a new user (admin)
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	email := NormalizeEmail(req.Email)
	phone := NormalizePhone(req.Phone)

	// Check email exists
	exists, _ := s.userRepo.ExistsByEmail(ctx, email)
	if exists {
		return nil, ErrEmailExists
	}

	// Check phone exists
	if phone != "" {
		exists, _ := s.userRepo.ExistsByPhone(ctx, phone)
		if exists {
			return nil, ErrPhoneExists
		}
	}

	// Check username exists
	if req.Username != "" {
		exists, _ := s.userRepo.ExistsByUsername(ctx, req.Username)
		if exists {
			return nil, ErrUsernameExists
		}
	}

	// Validate and hash password
	if err := s.passwordService.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	hash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	username := req.Username
	if username == "" {
		username = generateUsernameFromEmail(email)
	}

	var phonePtr *string
	if phone != "" {
		phonePtr = &phone
	}
	user := &models.User{
		Email:        email,
		Phone:        phonePtr,
		Username:     username,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsActive:     req.IsActive,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Assign roles
	for _, roleID := range req.RoleIDs {
		s.userRepo.AssignRole(ctx, user.ID, roleID)
	}

	return s.userRepo.GetWithRoles(ctx, user.ID)
}

// UpdateUserRequest represents admin user update request
type UpdateUserRequest struct {
	FirstName     string
	LastName      string
	Phone         string
	IsActive      bool
	EmailVerified bool
	PhoneVerified bool
	RoleIDs       []uuid.UUID
}

// UpdateUser updates a user (admin)
func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UpdateUserRequest) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	phone := NormalizePhone(req.Phone)
	if phone != "" && (user.Phone == nil || phone != *user.Phone) {
		exists, _ := s.userRepo.ExistsByPhone(ctx, phone)
		if exists {
			return nil, ErrPhoneExists
		}
		user.Phone = &phone
	}

	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.IsActive = req.IsActive
	user.EmailVerified = req.EmailVerified
	user.PhoneVerified = req.PhoneVerified

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	// Update roles
	if len(req.RoleIDs) > 0 {
		// Remove all existing roles first
		for _, role := range user.Roles {
			s.userRepo.RemoveRole(ctx, userID, role.ID)
		}
		// Assign new roles
		for _, roleID := range req.RoleIDs {
			s.userRepo.AssignRole(ctx, userID, roleID)
		}
	}

	return s.userRepo.GetWithRoles(ctx, userID)
}

// DeleteUser soft deletes a user (admin)
func (s *UserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	return s.userRepo.Delete(ctx, userID)
}

// ToggleUserStatus toggles user active status (admin)
func (s *UserService) ToggleUserStatus(ctx context.Context, userID uuid.UUID, isActive bool) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrUserNotFound
	}

	user.IsActive = isActive
	return s.userRepo.Update(ctx, user)
}

// UnlockUser unlocks a locked user (admin)
func (s *UserService) UnlockUser(ctx context.Context, userID uuid.UUID) error {
	return s.userRepo.UnlockUser(ctx, userID)
}

// GetUserSessions returns user sessions
func (s *UserService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	return s.sessionRepo.GetByUserID(ctx, userID)
}

// RevokeUserSession revokes a session owned by the given user.
// Returns ErrUserNotFound for unknown sessions or sessions belonging to
// another user so that session existence is not leaked.
func (s *UserService) RevokeUserSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil || session.UserID != userID {
		return ErrUserNotFound
	}

	if err := s.sessionRepo.Revoke(ctx, sessionID); err != nil {
		return err
	}

	if err := s.sessionRepo.InvalidateCachedSession(ctx, sessionID.String()); err != nil {
		s.logger.Error(logging.Redis, logging.Delete, "Failed to invalidate cached session", map[logging.ExtraKey]interface{}{
			"sessionID": sessionID.String(),
			"error":     err.Error(),
		})
	}

	if session.RefreshToken != "" {
		if err := s.refreshTokenRepo.Revoke(ctx, session.RefreshToken); err != nil {
			s.logger.Error(logging.Redis, logging.Delete, "Failed to revoke refresh token", map[logging.ExtraKey]interface{}{
				"sessionID": sessionID.String(),
				"error":     err.Error(),
			})
		}
	}

	return nil
}
