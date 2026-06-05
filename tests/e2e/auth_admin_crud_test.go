//go:build e2e

package e2e_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_AdminUserLifecycle(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	email := e2e.UniqueEmail("admin-created")
	resp, body, err := c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "E2E", "lastName": "AdminCreated", "isActive": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated)
	userID := e2e.ExtractID(t, body)

	resp, body, err = c.WithHeaders(h).Do(http.MethodGet, "/api/v1/admin/users/"+userID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)

	resp, body, err = c.WithHeaders(h).Do(http.MethodPut, "/api/v1/admin/users/"+userID, map[string]any{
		"firstName": "Updated", "isActive": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)

	resp, body, err = c.WithHeaders(h).Do(http.MethodPatch, "/api/v1/admin/users/"+userID+"/status/inactive", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusBadRequest)

	resp, body, err = c.WithHeaders(h).Do(http.MethodDelete, "/api/v1/admin/users/"+userID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNoContent)
}

func TestAuth_AdminRoleLifecycle(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	roleName := fmt.Sprintf("e2e-role-%d", time.Now().UnixNano())
	resp, body, err := c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/roles", map[string]any{
		"name": roleName, "description": "e2e test role",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusConflict)
	roleID := e2e.ExtractID(t, body)

	resp, body, err = c.WithHeaders(h).Do(http.MethodGet, "/api/v1/admin/roles/"+roleID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)

	resp, body, err = c.WithHeaders(h).Do(http.MethodDelete, "/api/v1/admin/roles/"+roleID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNoContent, http.StatusBadRequest)
}
