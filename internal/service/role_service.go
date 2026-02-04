package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
)

// RoleService handles role and permission management
type RoleService struct {
	roleRepo       repository.RoleRepository
	permissionRepo repository.PermissionRepository
}

func NewRoleService(
	roleRepo repository.RoleRepository,
	permissionRepo repository.PermissionRepository,
) *RoleService {
	return &RoleService{
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
	}
}

// --- Role Operations ---

// GetRole returns role by ID
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	return s.roleRepo.GetWithPermissions(ctx, id)
}

// GetRoleByName returns role by name
func (s *RoleService) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	return s.roleRepo.GetByName(ctx, name)
}

// ListRoles returns all roles
func (s *RoleService) ListRoles(ctx context.Context) ([]models.Role, error) {
	return s.roleRepo.List(ctx)
}

// CreateRoleRequest represents role creation request
type CreateRoleRequest struct {
	Name          string
	Description   string
	PermissionIDs []uuid.UUID
}

// CreateRole creates a new role
func (s *RoleService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	// Check if role exists
	existing, _ := s.roleRepo.GetByName(ctx, req.Name)
	if existing != nil {
		return nil, ErrRoleExists
	}

	role := &models.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, err
	}

	// Assign permissions
	for _, permID := range req.PermissionIDs {
		s.roleRepo.AssignPermission(ctx, role.ID, permID)
	}

	return s.roleRepo.GetWithPermissions(ctx, role.ID)
}

// UpdateRoleRequest represents role update request
type UpdateRoleRequest struct {
	Name          string
	Description   string
	PermissionIDs []uuid.UUID
}

// UpdateRole updates a role
func (s *RoleService) UpdateRole(ctx context.Context, id uuid.UUID, req *UpdateRoleRequest) (*models.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, ErrRoleNotFound
	}

	// Check if name is taken by another role
	if req.Name != role.Name {
		existing, _ := s.roleRepo.GetByName(ctx, req.Name)
		if existing != nil && existing.ID != id {
			return nil, ErrRoleExists
		}
	}

	role.Name = req.Name
	role.Description = req.Description

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, err
	}

	// Update permissions
	if len(req.PermissionIDs) > 0 {
		// Get current permissions
		roleWithPerms, _ := s.roleRepo.GetWithPermissions(ctx, id)
		if roleWithPerms != nil {
			for _, perm := range roleWithPerms.Permissions {
				s.roleRepo.RemovePermission(ctx, id, perm.ID)
			}
		}
		// Assign new permissions
		for _, permID := range req.PermissionIDs {
			s.roleRepo.AssignPermission(ctx, id, permID)
		}
	}

	return s.roleRepo.GetWithPermissions(ctx, id)
}

// DeleteRole deletes a role
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if role == nil {
		return ErrRoleNotFound
	}

	// Don't allow deleting system roles
	if role.Name == models.RoleAdmin || role.Name == models.RoleUser || role.Name == models.RoleService {
		return ErrCannotDeleteSystemRole
	}

	return s.roleRepo.Delete(ctx, id)
}

// --- Permission Operations ---

// GetPermission returns permission by ID
func (s *RoleService) GetPermission(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	return s.permissionRepo.GetByID(ctx, id)
}

// ListPermissions returns all permissions
func (s *RoleService) ListPermissions(ctx context.Context) ([]models.Permission, error) {
	return s.permissionRepo.List(ctx)
}

// ListPermissionsByResource returns permissions by resource
func (s *RoleService) ListPermissionsByResource(ctx context.Context, resource string) ([]models.Permission, error) {
	return s.permissionRepo.ListByResource(ctx, resource)
}

// CreatePermissionRequest represents permission creation request
type CreatePermissionRequest struct {
	Name        string
	Description string
	Resource    string
	Action      string
}

// CreatePermission creates a new permission
func (s *RoleService) CreatePermission(ctx context.Context, req *CreatePermissionRequest) (*models.Permission, error) {
	// Check if permission exists
	existing, _ := s.permissionRepo.GetByName(ctx, req.Name)
	if existing != nil {
		return nil, ErrPermissionExists
	}

	perm := &models.Permission{
		Name:        req.Name,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
	}

	if err := s.permissionRepo.Create(ctx, perm); err != nil {
		return nil, err
	}

	return perm, nil
}

// UpdatePermissionRequest represents permission update request
type UpdatePermissionRequest struct {
	Name        string
	Description string
	Resource    string
	Action      string
}

// UpdatePermission updates a permission
func (s *RoleService) UpdatePermission(ctx context.Context, id uuid.UUID, req *UpdatePermissionRequest) (*models.Permission, error) {
	perm, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if perm == nil {
		return nil, ErrPermissionNotFound
	}

	// Check if name is taken
	if req.Name != perm.Name {
		existing, _ := s.permissionRepo.GetByName(ctx, req.Name)
		if existing != nil && existing.ID != id {
			return nil, ErrPermissionExists
		}
	}

	perm.Name = req.Name
	perm.Description = req.Description
	perm.Resource = req.Resource
	perm.Action = req.Action

	if err := s.permissionRepo.Update(ctx, perm); err != nil {
		return nil, err
	}

	return perm, nil
}

// DeletePermission deletes a permission
func (s *RoleService) DeletePermission(ctx context.Context, id uuid.UUID) error {
	perm, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if perm == nil {
		return ErrPermissionNotFound
	}

	return s.permissionRepo.Delete(ctx, id)
}

// --- Role Permission Assignment ---

// AssignPermissionToRole assigns a permission to a role
func (s *RoleService) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return s.roleRepo.AssignPermission(ctx, roleID, permissionID)
}

// RemovePermissionFromRole removes a permission from a role
func (s *RoleService) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return s.roleRepo.RemovePermission(ctx, roleID, permissionID)
}

// HasPermission checks if role has permission
func (s *RoleService) HasPermission(ctx context.Context, roleID uuid.UUID, permissionName string) (bool, error) {
	return s.roleRepo.HasPermission(ctx, roleID, permissionName)
}
