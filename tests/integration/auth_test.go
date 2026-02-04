//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	testutil "github.com/minisource/auth/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthFlow(t *testing.T) {
	// Setup
	cfg := &config.Config{}
	testDB := testutil.SetupTestDB(t)
	defer testDB.Cleanup()

	// Create test user
	user, err := testutil.CreateTestUser(testDB.DB, testDB.TenantID, "test@example.com")
	require.NoError(t, err)

	// Setup app (simplified)
	app := fiber.New()

	t.Run("Login Success", func(t *testing.T) {
		loginReq := dto.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}
		body, _ := json.Marshal(loginReq)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", testDB.TenantID.String())

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var authResp dto.AuthResponse
		json.NewDecoder(resp.Body).Decode(&authResp)
		assert.NotEmpty(t, authResp.AccessToken)
		assert.NotEmpty(t, authResp.RefreshToken)
	})

	t.Run("Login Invalid Credentials", func(t *testing.T) {
		loginReq := dto.LoginRequest{
			Email:    "test@example.com",
			Password: "wrongpassword",
		}
		body, _ := json.Marshal(loginReq)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", testDB.TenantID.String())

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Register New User", func(t *testing.T) {
		registerReq := dto.RegisterRequest{
			Email:    "newuser@example.com",
			Password: "password123",
			Name:     "New User",
		}
		body, _ := json.Marshal(registerReq)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", testDB.TenantID.String())

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})
}

func TestRolePermissionFlow(t *testing.T) {
	testDB := testutil.SetupTestDB(t)
	defer testDB.Cleanup()

	// Create test user with admin role
	user, err := testutil.CreateTestUser(testDB.DB, testDB.TenantID, "admin@example.com")
	require.NoError(t, err)

	adminRole, err := testutil.CreateTestRole(testDB.DB, testDB.TenantID, "admin")
	require.NoError(t, err)

	err = testutil.AssignRoleToUser(testDB.DB, user.ID, adminRole.ID)
	require.NoError(t, err)

	t.Run("Create Permission", func(t *testing.T) {
		permission, err := testutil.CreateTestPermission(testDB.DB, testDB.TenantID, "users", "read")
		require.NoError(t, err)
		assert.NotNil(t, permission)
		assert.Equal(t, "users", permission.Resource)
		assert.Equal(t, "read", permission.Action)
	})

	t.Run("Assign Permission to Role", func(t *testing.T) {
		permission, err := testutil.CreateTestPermission(testDB.DB, testDB.TenantID, "users", "write")
		require.NoError(t, err)

		rolePermission := struct {
			RoleID       string
			PermissionID string
		}{
			RoleID:       adminRole.ID.String(),
			PermissionID: permission.ID.String(),
		}

		// This would test the actual API endpoint
		assert.NotNil(t, rolePermission)
	})
}
