//go:build e2e

package e2e_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_ResetPasswordFlow(t *testing.T) {
	c := authClient(t)
	email := strings.ToLower(e2e.UniqueEmail("reset"))
	oldPassword := testUserPassword
	newPassword := "NewPass123!"

	resp, body, err := c.Do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": oldPassword, "firstName": "Reset", "lastName": "User",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated)

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/forgot-password", map[string]any{
		"email": email,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skip("forgot-password rate limited")
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusAccepted)

	code := e2e.OTPFromRedis(t, email, "password_reset")

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/reset-password", map[string]any{
		"target":      email,
		"code":        code,
		"newPassword": newPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)

	resp, body, err = c.Do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": email, "password": oldPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatal("old password should not work after reset")
	}

	token := e2e.LoginAuth(t, c.BaseURL, email, newPassword)
	if token == "" {
		t.Fatal("login with new password failed")
	}
}
