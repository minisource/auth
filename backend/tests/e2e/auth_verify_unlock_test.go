//go:build e2e

package e2e_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_VerifyEmailFlow(t *testing.T) {
	c := authClient(t)
	email := strings.ToLower(e2e.UniqueEmail("verify"))

	resp, body, err := c.Do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "Verify", "lastName": "User",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated)

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/resend-verification", map[string]any{
		"email": email,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skip("verification rate limited")
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusAccepted)

	code := e2e.OTPFromRedis(t, email, "email_verification")

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/verify-email", map[string]any{
		"target": email, "code": code,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestAuth_AdminUnlockUser(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)
	email := e2e.UniqueEmail("unlock")

	resp, body, err := c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"email": email, "password": testUserPassword, "firstName": "Lock", "lastName": "Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated)
	userID := e2e.ExtractID(t, body)

	resp, body, err = c.WithHeaders(h).Do(http.MethodPost, "/api/v1/admin/users/"+userID+"/unlock", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}
