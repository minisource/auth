//go:build e2e

package e2e_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/minisource/go-common/common"
	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_SetPasswordForOTPUser(t *testing.T) {
	c := authClient(t)
	phone := "0912" + time.Now().Format("050405")

	resp, body, err := c.Do(http.MethodPost, "/api/v1/auth/otp/send", map[string]any{
		"phone": phone, "type": "login",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)

	target := common.NormalizeIranPhone(phone)
	code := e2e.OTPFromRedis(t, target, "login")

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/otp/verify", map[string]any{
		"target": phone, "code": code, "type": "login",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)

	var parsed map[string]any
	e2e.ParseJSON(t, body, &parsed)
	token := e2e.GetString(parsed, "data", "accessToken")
	if token == "" {
		token = e2e.GetString(parsed, "accessToken")
	}
	if token == "" {
		t.Fatalf("no access token after otp verify: %s", string(body))
	}

	newPass := "OtpSetPass123!"
	resp, body, err = c.WithHeaders(e2e.Bearer(token)).Do(http.MethodPost, "/api/v1/users/me/password/set", map[string]any{
		"password": newPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusBadRequest)
}

func TestAuth_UnlinkGoogleWhenNotLinked(t *testing.T) {
	c := authClient(t)
	email := e2e.UniqueEmail("nolink")
	_, _, _ = c.Do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "No", "lastName": "Google",
	})
	token := e2e.LoginAuth(t, c.BaseURL, email, testUserPassword)

	resp, body, err := c.WithHeaders(e2e.Bearer(token)).Do(http.MethodDelete, "/api/v1/users/me/linked-accounts/google", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusBadRequest, http.StatusNotFound)
}

func TestAuth_AdminPermissionUpdate(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	permName := fmt.Sprintf("e2e:perm:upd:%d", time.Now().UnixNano())
	resp, body, err := c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/permissions", map[string]any{
		"name": permName, "resource": "e2e", "action": "write", "description": "before update",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusConflict)
	permID := e2e.ExtractID(t, body)

	resp, body, err = c.WithHeaders(h).Do(http.MethodPut, "/api/v1/admin/permissions/"+permID, map[string]any{
		"name": permName, "resource": "e2e", "action": "write", "description": "after update",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusBadRequest, http.StatusNotFound)

	resp, body, err = c.WithHeaders(h).Do(http.MethodDelete, "/api/v1/admin/permissions/"+permID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNoContent, http.StatusBadRequest)
}
