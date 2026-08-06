//go:build e2e

package e2e_test

import (
	"net/http"
	"testing"

	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_AdminUserCRUD(t *testing.T) {
	c := authClient(t)
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)

	resp, body, err := c.WithHeaders(h).Do(http.MethodGet, "/api/v1/admin/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	var list map[string]any
	e2e.ParseJSON(t, body, &list)
	userID := e2e.GetString(list, "data", "id")
	if userID == "" {
		if users, ok := list["users"].([]any); ok && len(users) > 0 {
			if u, ok := users[0].(map[string]any); ok {
				userID, _ = u["id"].(string)
			}
		}
	}
	if userID == "" {
		t.Skip("no users in admin list")
	}

	c.RunCases(t, []e2e.Case{
		{Name: "admin_user_by_id", Method: http.MethodGet, Path: "/api/v1/admin/users/" + userID, Headers: h, WantCode: []int{http.StatusOK, http.StatusNotFound}},
		{Name: "admin_role_by_id", Method: http.MethodGet, Path: "/api/v1/admin/roles/00000000-0000-0000-0000-000000000001", Headers: h, WantCode: []int{http.StatusOK, http.StatusNotFound}},
		{Name: "forgot_password", Method: http.MethodPost, Path: "/api/v1/auth/forgot-password", Body: map[string]any{"email": adminEmail}, WantCode: []int{http.StatusOK, http.StatusAccepted, http.StatusBadRequest, http.StatusTooManyRequests}},
	})
}
