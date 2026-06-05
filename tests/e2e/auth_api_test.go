//go:build e2e

package e2e_test

import (
	"net/http"
	"testing"

	"github.com/minisource/go-common/testing/e2e"
)

const (
	defaultAuthURL     = "http://127.0.0.1:9001"
	adminEmail         = "admin@example.com"
	adminPassword      = "AdminPass123!"
	serviceAuthID      = "auth-service"
	serviceAuthSecret  = "auth-service-secret-key"
	testUserPassword   = "TestPass123"
)

func authClient(t *testing.T) *e2e.Client {
	t.Helper()
	c := e2e.NewClient(e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL), nil)
	c.RequireUp(t, "/health")
	return c
}

func TestAuth_PublicEndpoints(t *testing.T) {
	c := authClient(t)
	email := e2e.UniqueEmail("user")

	c.RunCases(t, []e2e.Case{
		{Name: "health", Method: http.MethodGet, Path: "/health", WantCode: []int{http.StatusOK}},
		{Name: "ready", Method: http.MethodGet, Path: "/ready", WantCode: []int{http.StatusOK}},
		{Name: "metrics", Method: http.MethodGet, Path: "/metrics", WantCode: []int{http.StatusOK, http.StatusInternalServerError}},
		{Name: "register", Method: http.MethodPost, Path: "/api/v1/auth/register", Body: map[string]any{
			"email": email, "password": testUserPassword, "firstName": "E2E", "lastName": "User",
		}, WantCode: []int{http.StatusOK, http.StatusCreated}},
		{Name: "login", Method: http.MethodPost, Path: "/api/v1/auth/login", Body: map[string]any{
			"email": email, "password": testUserPassword,
		}, WantCode: []int{http.StatusOK}},
		{Name: "otp_send", Method: http.MethodPost, Path: "/api/v1/auth/otp/send", Body: map[string]any{
			"phone": "0912" + "5551234", "type": "login",
		}, WantCode: []int{http.StatusOK, http.StatusTooManyRequests}},
		{Name: "forgot_password", Method: http.MethodPost, Path: "/api/v1/auth/forgot-password", Body: map[string]any{
			"email": email,
		}, WantCode: []int{http.StatusOK, http.StatusAccepted, http.StatusBadRequest}},
	})
}

func TestAuth_ServiceAuth(t *testing.T) {
	c := authClient(t)
	token := e2e.ServiceToken(t, c.BaseURL, serviceAuthID, serviceAuthSecret)

	c.RunCases(t, []e2e.Case{
		{Name: "service_validate", Method: http.MethodGet, Path: "/api/v1/service/validate",
			Headers: e2e.Bearer(token), WantCode: []int{http.StatusOK}},
	})
}

func TestAuth_UserEndpoints(t *testing.T) {
	c := authClient(t)
	email := e2e.UniqueEmail("me")
	_, _, _ = c.Do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "A", "lastName": "B",
	})
	token := e2e.LoginAuth(t, c.BaseURL, email, testUserPassword)
	h := e2e.Bearer(token)

	c.RunCases(t, []e2e.Case{
		{Name: "me_get", Method: http.MethodGet, Path: "/api/v1/users/me", Headers: h, WantCode: []int{http.StatusOK}},
		{Name: "me_put", Method: http.MethodPut, Path: "/api/v1/users/me", Headers: h, Body: map[string]any{
			"firstName": "Updated",
		}, WantCode: []int{http.StatusOK}},
		{Name: "sessions", Method: http.MethodGet, Path: "/api/v1/users/me/sessions", Headers: h, WantCode: []int{http.StatusOK}},
		{Name: "linked_accounts", Method: http.MethodGet, Path: "/api/v1/users/me/linked-accounts", Headers: h, WantCode: []int{http.StatusOK}},
		{Name: "logout", Method: http.MethodPost, Path: "/api/v1/auth/logout", Headers: h, WantCode: []int{http.StatusOK}},
	})
}

func TestAuth_TokenValidateEndpoint(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	resp, body, err := c.WithHeaders(e2e.Bearer(token)).Do(http.MethodGet, "/api/v1/tokens/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestAuth_RefreshToken(t *testing.T) {
	c := authClient(t)
	email := e2e.UniqueEmail("refresh")
	_, _, _ = c.Do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "R", "lastName": "T",
	})
	resp, body, err := c.Do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": email, "password": testUserPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	var login map[string]any
	e2e.ParseJSON(t, body, &login)
	refresh := e2e.GetString(login, "data", "refreshToken")
	if refresh == "" {
		t.Skip("no refreshToken in login response")
	}
	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/refresh", map[string]any{"refreshToken": refresh})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusUnauthorized)
}

func TestAuth_AdminEndpoints(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	c.RunCases(t, []e2e.Case{
		{Name: "admin_users_list", Method: http.MethodGet, Path: "/api/v1/admin/users", Headers: h, WantCode: []int{http.StatusOK}},
		{Name: "admin_roles_list", Method: http.MethodGet, Path: "/api/v1/admin/roles", Headers: h, WantCode: []int{http.StatusOK}},
		{Name: "admin_permissions_list", Method: http.MethodGet, Path: "/api/v1/admin/permissions", Headers: h, WantCode: []int{http.StatusOK}},
		{Name: "admin_create_permission", Method: http.MethodPost, Path: "/api/v1/admin/permissions", Headers: h, Body: map[string]any{
			"name": "e2e:test", "resource": "e2e", "action": "read", "description": "e2e test permission",
		}, WantCode: []int{http.StatusOK, http.StatusCreated, http.StatusConflict, http.StatusInternalServerError}},
	})
}

func TestAuth_GoogleOAuthMock(t *testing.T) {
	mockURL := e2e.BaseURLFromEnv("MOCK_BASE_URL", "http://127.0.0.1:9191")
	mock := e2e.NewClient(mockURL, nil)
	if _, _, err := mock.Do(http.MethodGet, "/health", nil); err != nil {
		t.Skip("dev-mocks not running")
	}

	c := authClient(t)
	resp, body, err := c.Do(http.MethodGet, "/api/v1/auth/google", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	var parsed map[string]any
	e2e.ParseJSON(t, body, &parsed)
	url := e2e.GetString(parsed, "url")
	if url == "" {
		t.Fatalf("missing oauth url: %s", string(body))
	}

	resp, body, err = c.Do(http.MethodGet, "/api/v1/auth/google/callback?code=mock-auth-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}
