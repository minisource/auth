package testing

import (
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// CreateTestUser creates a test user
func CreateTestUser(db *gorm.DB, tenantID uuid.UUID, email string) (*models.User, error) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	user := &models.User{
		ID:            uuid.New(),
		TenantID:      &tenantID,
		Email:         email,
		Username:      email,
		FirstName:     "Test",
		LastName:      "User",
		PasswordHash:  string(hashedPassword),
		IsActive:      true,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := db.Create(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// CreateTestRole creates a test role
func CreateTestRole(db *gorm.DB, tenantID uuid.UUID, name string) (*models.Role, error) {
	role := &models.Role{
		ID:          uuid.New(),
		TenantID:    &tenantID,
		Name:        name,
		Description: "Test role",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.Create(role).Error; err != nil {
		return nil, err
	}

	return role, nil
}

// CreateTestPermission creates a test permission
func CreateTestPermission(db *gorm.DB, tenantID uuid.UUID, resource, action string) (*models.Permission, error) {
	permission := &models.Permission{
		ID:          uuid.New(),
		Name:        resource + "_" + action,
		Resource:    resource,
		Action:      action,
		Description: "Test permission",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.Create(permission).Error; err != nil {
		return nil, err
	}

	return permission, nil
}

// AssignRoleToUser assigns a role to a user
func AssignRoleToUser(db *gorm.DB, userID, roleID uuid.UUID) error {
	userRole := &models.UserRole{
		UserID: userID,
		RoleID: roleID,
	}
	return db.Create(userRole).Error
}

// CreateTestSession creates a test session
func CreateTestSession(db *gorm.DB, tenantID, userID uuid.UUID, token string) (*models.Session, error) {
	session := &models.Session{
		ID:           uuid.New(),
		TenantID:     &tenantID,
		UserID:       userID,
		AccessToken:  token,
		IsActive:     true,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		LastActiveAt: time.Now(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.Create(session).Error; err != nil {
		return nil, err
	}

	return session, nil
}
