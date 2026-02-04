package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
)

// UserService handles user management
type UserService struct {
	cfg             *config.Config
	userRepo        repository.UserRepository
	roleRepo        repository.RoleRepository
	sessionRepo     repository.SessionRepository
	passwordService *PasswordService
	logger          logging.Logger
}

func NewUserService(
	cfg *config.Config,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	sessionRepo repository.SessionRepository,
	passwordService *PasswordService,
	logger logging.Logger,
) *UserService {
	return &UserService{
		cfg:             cfg,
		userRepo:        userRepo,
		roleRepo:        roleRepo,
		sessionRepo:     sessionRepo,
		passwordService: passwordService,
		logger:          logger,
	}
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
	return s.userRepo.Update(ctx, user)
}

// GetUserByID returns user by ID (admin)
func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetWithRoles(ctx, userID)
}

// ListUsersRequest represents user list request
type ListUsersRequest struct {
	Page     int
	PageSize int
	Search   string
	RoleID   uuid.UUID
	IsActive *bool
}

// ListUsersResponse represents user list response
type ListUsersResponse struct {
	Users      []models.User `json:"users"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"pageSize"`
	TotalPages int           `json:"totalPages"`
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

	users, total, err := s.userRepo.ListWithFilters(ctx, req.Search, req.RoleID, req.IsActive, offset, req.PageSize)
	if err != nil {
		return nil, err
	}

	totalPages := int(total) / req.PageSize
	if int(total)%req.PageSize > 0 {
		totalPages++
	}

	return &ListUsersResponse{
		Users:      users,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
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

	user := &models.User{
		Email:        email,
		Phone:        phone,
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
	if phone != "" && phone != user.Phone {
		exists, _ := s.userRepo.ExistsByPhone(ctx, phone)
		if exists {
			return nil, ErrPhoneExists
		}
		user.Phone = phone
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
