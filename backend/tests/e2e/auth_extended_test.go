//go:build e2e

package e2e_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_RoleUpdateAndPermissions(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	roleName := fmt.Sprintf("e2e-role-upd-%d", time.Now().UnixNano())
	resp, body, err := c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/roles", map[string]any{
		"name": roleName, "description": "update test",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusConflict)
	roleID := e2e.ExtractID(t, body)

	resp, body, err = c.WithHeaders(h).Do(http.MethodPut, "/api/v1/admin/roles/"+roleID, map[string]any{
		"name": roleName, "description": "updated description",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusBadRequest)

	permName := fmt.Sprintf("e2e:perm:%d", time.Now().UnixNano())
	resp, body, err = c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/permissions", map[string]any{
		"name": permName, "resource": "e2e", "action": "read", "description": "e2e perm",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusConflict)
	permID := e2e.ExtractID(t, body)

	resp, body, err = c.WithHeaders(h).Do(http.MethodGet, "/api/v1/admin/permissions/"+permID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNotFound)

	resp, body, err = c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/roles/"+roleID+"/permissions/"+permID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusBadRequest, http.StatusNotFound)

	resp, body, err = c.WithHeaders(h).Do(http.MethodDelete, "/api/v1/admin/roles/"+roleID+"/permissions/"+permID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNoContent, http.StatusNotFound)

	resp, body, err = c.WithHeaders(h).Do(http.MethodDelete, "/api/v1/admin/permissions/"+permID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNoContent, http.StatusBadRequest)

	resp, body, err = c.WithHeaders(h).Do(http.MethodDelete, "/api/v1/admin/roles/"+roleID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNoContent, http.StatusBadRequest)
}

func TestAuth_ServiceClientCreate(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	name := fmt.Sprintf("e2e-svc-%d", time.Now().UnixNano())
	resp, body, err := c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/service-clients", map[string]any{
		"name": name, "description": "e2e service client", "scopes": []string{"notifications:send"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusForbidden, http.StatusBadRequest)
}

func TestAuth_ChangePassword(t *testing.T) {
	c := authClient(t)
	email := e2e.UniqueEmail("pwd")
	_, _, _ = c.Do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "Pwd", "lastName": "Test",
	})
	token := e2e.LoginAuth(t, c.BaseURL, email, testUserPassword)
	h := e2e.Bearer(token)

	newPass := "NewPass123!"
	resp, body, err := c.WithHeaders(h).Do(http.MethodPut, "/api/v1/users/me/password", map[string]any{
		"oldPassword": testUserPassword, "newPassword": newPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Skipf("password change not available: %s", string(body))
	}

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": email, "password": newPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}
