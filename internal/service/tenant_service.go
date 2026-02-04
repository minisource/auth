package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/common"
	"github.com/minisource/go-common/logging"
	service_errors "github.com/minisource/go-common/service_errors"
)

type TenantService interface {
	// Tenant CRUD
	CreateTenant(ctx context.Context, name, slug string, ownerID uuid.UUID) (*models.Tenant, error)
	GetTenantByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*models.Tenant, error)
	GetTenantByDomain(ctx context.Context, domain string) (*models.Tenant, error)
	GetDefaultTenant(ctx context.Context) (*models.Tenant, error)
	UpdateTenant(ctx context.Context, id uuid.UUID, updates map[string]interface{}) (*models.Tenant, error)
	DeleteTenant(ctx context.Context, id uuid.UUID) error
	ListTenants(ctx context.Context, page, pageSize int) ([]models.Tenant, int64, error)
	SetTenantStatus(ctx context.Context, id uuid.UUID, status models.TenantStatus) error

	// Member management
	AddMember(ctx context.Context, tenantID, userID uuid.UUID, roleID *uuid.UUID) error
	RemoveMember(ctx context.Context, tenantID, userID uuid.UUID) error
	GetTenantMembers(ctx context.Context, tenantID uuid.UUID) ([]models.TenantMember, error)
	GetUserTenants(ctx context.Context, userID uuid.UUID) ([]models.TenantMember, error)
	UpdateMemberRole(ctx context.Context, tenantID, userID uuid.UUID, roleID uuid.UUID) error
	SetDefaultTenant(ctx context.Context, userID, tenantID uuid.UUID) error
	IsMember(ctx context.Context, tenantID, userID uuid.UUID) (bool, error)

	// Invitations
	InviteMember(ctx context.Context, tenantID uuid.UUID, email, role string, invitedBy uuid.UUID) (*models.TenantInvitation, error)
	AcceptInvitation(ctx context.Context, token string, userID uuid.UUID) error
	GetPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]models.TenantInvitation, error)
	RevokeInvitation(ctx context.Context, invitationID uuid.UUID) error

	// Settings
	UpdateSettings(ctx context.Context, tenantID uuid.UUID, settings models.TenantSettings) error
	UpdateLimits(ctx context.Context, tenantID uuid.UUID, limits models.TenantLimits) error
}

type tenantService struct {
	tenantRepo repository.TenantRepository
	userRepo   repository.UserRepository
	roleRepo   repository.RoleRepository
	logger     logging.Logger
}

func NewTenantService(
	tenantRepo repository.TenantRepository,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	logger logging.Logger,
) TenantService {
	return &tenantService{
		tenantRepo: tenantRepo,
		userRepo:   userRepo,
		roleRepo:   roleRepo,
		logger:     logger,
	}
}

func (s *tenantService) CreateTenant(ctx context.Context, name, slug string, ownerID uuid.UUID) (*models.Tenant, error) {
	// Check if slug is already taken
	existing, err := s.tenantRepo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "A tenant with this slug already exists",
		}
	}

	// Create tenant with default settings and limits
	tenant := &models.Tenant{
		ID:     uuid.New(),
		Name:   name,
		Slug:   slug,
		Status: models.TenantStatusActive,
		Settings: models.TenantSettings{
			AllowUserRegistration: true,
			RequireEmailVerified:  true,
			RequirePhoneVerified:  false,
			AllowedAuthMethods:    []string{"password", "otp"},
			SessionTimeout:        24, // hours
			MaxSessionsPerUser:    5,
		},
		Limits: models.TenantLimits{
			MaxUsers:          100,
			MaxRoles:          20,
			MaxServiceClients: 10,
			MaxMembersPerRole: 50,
		},
		Plan:         "free",
		BillingCycle: "monthly",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		return nil, err
	}

	// Add owner as first member with admin role
	// First try to find an admin role for this tenant
	adminRole, _ := s.roleRepo.GetByName(ctx, "admin")
	var roleID *uuid.UUID
	if adminRole != nil {
		roleID = &adminRole.ID
	}

	member := &models.TenantMember{
		TenantID:  tenant.ID,
		UserID:    ownerID,
		RoleID:    roleID,
		IsOwner:   true,
		IsDefault: true,
		JoinedAt:  time.Now(),
	}

	if err := s.tenantRepo.AddMember(ctx, member); err != nil {
		// Rollback tenant creation
		s.tenantRepo.Delete(ctx, tenant.ID)
		return nil, err
	}

	s.logger.Info(logging.General, logging.Create, "Tenant created", map[logging.ExtraKey]interface{}{
		logging.Name: name,
		logging.Slug: slug,
	})

	return tenant, nil
}

func (s *tenantService) GetTenantByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}
	return tenant, nil
}

func (s *tenantService) GetTenantBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	tenant, err := s.tenantRepo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}
	return tenant, nil
}

func (s *tenantService) GetTenantByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	tenant, err := s.tenantRepo.GetByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}
	return tenant, nil
}

func (s *tenantService) GetDefaultTenant(ctx context.Context) (*models.Tenant, error) {
	return s.tenantRepo.GetDefault(ctx)
}

func (s *tenantService) UpdateTenant(ctx context.Context, id uuid.UUID, updates map[string]interface{}) (*models.Tenant, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}

	// Apply updates
	if name, ok := updates["name"].(string); ok {
		tenant.Name = name
	}
	if domain, ok := updates["domain"].(string); ok {
		tenant.Domain = domain
	}
	if logo, ok := updates["logo_url"].(string); ok {
		tenant.Logo = logo
	}
	if description, ok := updates["description"].(string); ok {
		tenant.Description = description
	}

	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

func (s *tenantService) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	tenant, err := s.tenantRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if tenant == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}

	if tenant.IsDefault {
		return &service_errors.ServiceError{
			EndUserMessage: "Cannot delete the default tenant",
		}
	}

	return s.tenantRepo.Delete(ctx, id)
}

func (s *tenantService) ListTenants(ctx context.Context, page, pageSize int) ([]models.Tenant, int64, error) {
	offset := (page - 1) * pageSize
	return s.tenantRepo.List(ctx, offset, pageSize)
}

func (s *tenantService) SetTenantStatus(ctx context.Context, id uuid.UUID, status models.TenantStatus) error {
	tenant, err := s.tenantRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if tenant == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}

	tenant.Status = status
	tenant.UpdatedAt = time.Now()

	return s.tenantRepo.Update(ctx, tenant)
}

// Member management
func (s *tenantService) AddMember(ctx context.Context, tenantID, userID uuid.UUID, roleID *uuid.UUID) error {
	// Check if already a member
	existing, err := s.tenantRepo.GetMember(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if existing != nil {
		return &service_errors.ServiceError{
			EndUserMessage: "User is already a member of this tenant",
		}
	}

	// Check tenant limits
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}

	members, err := s.tenantRepo.GetMembersByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(members) >= tenant.Limits.MaxUsers {
		return &service_errors.ServiceError{
			EndUserMessage: "Tenant has reached maximum member limit",
		}
	}

	member := &models.TenantMember{
		TenantID:  tenantID,
		UserID:    userID,
		RoleID:    roleID,
		IsOwner:   false,
		IsDefault: len(members) == 0, // First membership is default
		JoinedAt:  time.Now(),
	}

	return s.tenantRepo.AddMember(ctx, member)
}

func (s *tenantService) RemoveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	member, err := s.tenantRepo.GetMember(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if member == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "User is not a member of this tenant",
		}
	}

	if member.IsOwner {
		return &service_errors.ServiceError{
			EndUserMessage: "Cannot remove the tenant owner",
		}
	}

	return s.tenantRepo.RemoveMember(ctx, tenantID, userID)
}

func (s *tenantService) GetTenantMembers(ctx context.Context, tenantID uuid.UUID) ([]models.TenantMember, error) {
	return s.tenantRepo.GetMembersByTenant(ctx, tenantID)
}

func (s *tenantService) GetUserTenants(ctx context.Context, userID uuid.UUID) ([]models.TenantMember, error) {
	return s.tenantRepo.GetMembersByUser(ctx, userID)
}

func (s *tenantService) UpdateMemberRole(ctx context.Context, tenantID, userID uuid.UUID, roleID uuid.UUID) error {
	member, err := s.tenantRepo.GetMember(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if member == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "User is not a member of this tenant",
		}
	}

	member.RoleID = &roleID
	return s.tenantRepo.UpdateMember(ctx, member)
}

func (s *tenantService) SetDefaultTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	// Verify membership
	member, err := s.tenantRepo.GetMember(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if member == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "User is not a member of this tenant",
		}
	}

	return s.tenantRepo.SetDefaultTenant(ctx, userID, tenantID)
}

func (s *tenantService) IsMember(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	member, err := s.tenantRepo.GetMember(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	return member != nil, nil
}

// Invitations
func (s *tenantService) InviteMember(ctx context.Context, tenantID uuid.UUID, email, role string, invitedBy uuid.UUID) (*models.TenantInvitation, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "Tenant not found",
		}
	}

	// Generate secure token
	token := common.GenerateUniqueKey()

	// Find role by name if specified
	var roleID *uuid.UUID
	if role != "" {
		roleObj, _ := s.roleRepo.GetByName(ctx, role)
		if roleObj != nil {
			roleID = &roleObj.ID
		}
	}

	invitation := &models.TenantInvitation{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Email:     email,
		RoleID:    roleID,
		Token:     token,
		InvitedBy: invitedBy,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt: time.Now(),
	}

	if err := s.tenantRepo.CreateInvitation(ctx, invitation); err != nil {
		return nil, err
	}

	return invitation, nil
}

func (s *tenantService) AcceptInvitation(ctx context.Context, token string, userID uuid.UUID) error {
	invitation, err := s.tenantRepo.GetInvitationByToken(ctx, token)
	if err != nil {
		return err
	}
	if invitation == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "Invalid or expired invitation",
		}
	}

	if time.Now().After(invitation.ExpiresAt) {
		return &service_errors.ServiceError{
			EndUserMessage: "Invitation has expired",
		}
	}

	// Add member with role from invitation
	if err := s.AddMember(ctx, invitation.TenantID, userID, invitation.RoleID); err != nil {
		return err
	}

	// Mark invitation as accepted
	return s.tenantRepo.AcceptInvitation(ctx, invitation.ID)
}

func (s *tenantService) GetPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]models.TenantInvitation, error) {
	return s.tenantRepo.GetPendingInvitations(ctx, tenantID)
}

func (s *tenantService) RevokeInvitation(ctx context.Context, invitationID uuid.UUID) error {
	return s.tenantRepo.DeleteInvitation(ctx, invitationID)
}

// Settings
func (s *tenantService) UpdateSettings(ctx context.Context, tenantID uuid.UUID, settings models.TenantSettings) error {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return errors.New("tenant not found")
	}

	tenant.Settings = settings
	tenant.UpdatedAt = time.Now()

	return s.tenantRepo.Update(ctx, tenant)
}

func (s *tenantService) UpdateLimits(ctx context.Context, tenantID uuid.UUID, limits models.TenantLimits) error {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return errors.New("tenant not found")
	}

	tenant.Limits = limits
	tenant.UpdatedAt = time.Now()

	return s.tenantRepo.Update(ctx, tenant)
}
