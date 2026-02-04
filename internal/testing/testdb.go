package testing

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestDB holds test database connection
type TestDB struct {
	DB       *gorm.DB
	TenantID uuid.UUID
	t        *testing.T
}

// SetupTestDB creates a test database connection
func SetupTestDB(t *testing.T) *TestDB {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnvOrDefault("TEST_DB_HOST", "localhost"),
		getEnvOrDefault("TEST_DB_PORT", "5432"),
		getEnvOrDefault("TEST_DB_USER", "postgres"),
		getEnvOrDefault("TEST_DB_PASSWORD", "postgres"),
		getEnvOrDefault("TEST_DB_NAME", "auth_test"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err, "failed to connect to test database")

	// Create test tenant
	tenantID := uuid.New()

	return &TestDB{
		DB:       db,
		TenantID: tenantID,
		t:        t,
	}
}

// Cleanup removes test data
func (db *TestDB) Cleanup() {
	// Clean up test data
	db.DB.Exec("DELETE FROM sessions WHERE tenant_id = ?", db.TenantID)
	db.DB.Exec("DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE tenant_id = ?)", db.TenantID)
	db.DB.Exec("DELETE FROM users WHERE tenant_id = ?", db.TenantID)
	db.DB.Exec("DELETE FROM roles WHERE tenant_id = ?", db.TenantID)
	db.DB.Exec("DELETE FROM permissions WHERE tenant_id = ?", db.TenantID)
}

// SetTenantContext sets the tenant context for RLS
func (db *TestDB) SetTenantContext(ctx context.Context) context.Context {
	db.DB.Exec("SET app.current_tenant_id = ?", db.TenantID.String())
	return ctx
}

func getEnvOrDefault(key, defaultValue string) string {
	// Simple env getter for tests
	return defaultValue
}
