//go:build e2e

package e2e_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/minisource/go-common/common"
	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_OTPVerifyAndLogin(t *testing.T) {
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
		"target": phone,
		"code":   code,
		"type":   "login",
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
}
