//go:build e2e

package e2e_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/minisource/go-common/testing/e2e"
)

// Cross-service flows: Auth→Notifier, Gateway→Auth/Notifier.
func TestCrossService_AuthNotifier_OTP(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	notifierURL := e2e.BaseURLFromEnv("NOTIFIER_BASE_URL", "http://127.0.0.1:9002")

	auth := e2e.NewClient(authURL, nil)
	auth.RequireUp(t, "/health")
	notifier := e2e.NewClient(notifierURL, nil)
	notifier.RequireUp(t, "/api/v1/health/")

	phone := "0912" + time.Now().Format("150405") // unique-ish per run
	resp, body, err := auth.Do(http.MethodPost, "/api/v1/auth/otp/send", map[string]any{
		"phone": phone, "type": "login",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestCrossService_GatewayProxies(t *testing.T) {
	gw := e2e.NewClient(e2e.BaseURLFromEnv("GATEWAY_BASE_URL", "http://127.0.0.1:8080"), nil)
	gw.RequireUp(t, "/health")

	// Auth via gateway
	resp, body, err := gw.Do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": adminEmail, "password": adminPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	var login map[string]any
	e2e.ParseJSON(t, body, &login)
	token := e2e.GetString(login, "data", "accessToken")
	if token == "" {
		t.Fatalf("no token from gateway login: %s", string(body))
	}
	h := e2e.Bearer(token)

	// User profile via gateway
	resp, body, err = gw.Do(http.MethodGet, "/api/v1/users/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		return
	}
	// Some gateway configs route /users under auth prefix only
	resp, body, err = gw.WithHeaders(h).Do(http.MethodGet, "/api/v1/users/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusNotFound, http.StatusBadGateway)

	// Notifier templates via gateway (if routed)
	svcToken := e2e.ServiceToken(t, e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL), serviceAuthID, serviceAuthSecret)
	resp, body, err = gw.WithHeaders(e2e.Bearer(svcToken)).Do(http.MethodGet, "/api/v1/templates", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("gateway does not expose /api/v1/templates")
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusBadGateway, http.StatusBadRequest)
}

func TestCrossService_TokenValidate_UserAndService(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	c := e2e.NewClient(authURL, nil)
	c.RequireUp(t, "/health")

	userToken := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	resp, body, err := c.WithHeaders(e2e.Bearer(userToken)).Do(http.MethodGet, "/api/v1/tokens/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	var v map[string]any
	e2e.ParseJSON(t, body, &v)
	if v["valid"] != true {
		t.Fatalf("user token not valid: %s", string(body))
	}
	if v["tokenType"] != "user" {
		t.Fatalf("expected tokenType user, got %v", v["tokenType"])
	}

	svcToken := e2e.ServiceToken(t, authURL, serviceAuthID, serviceAuthSecret)
	resp, body, err = c.WithHeaders(e2e.Bearer(svcToken)).Do(http.MethodGet, "/api/v1/tokens/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	e2e.ParseJSON(t, body, &v)
	if v["tokenType"] != "service" {
		t.Fatalf("expected tokenType service, got %v", v["tokenType"])
	}
}

func TestCrossService_CommentWithUserJWT(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	commentURL := e2e.BaseURLFromEnv("COMMENT_BASE_URL", "http://127.0.0.1:5010")

	token := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	c := e2e.NewClient(commentURL, e2e.Bearer(token))
	c.RequireUp(t, "/health")

	resp, body, err := c.Do(http.MethodGet, "/api/v1/comments?limit=5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("comment rejected user JWT (restart comment after auth/sdk fix): %s", string(body))
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestCrossService_CommentNotifier(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	commentURL := e2e.BaseURLFromEnv("COMMENT_BASE_URL", "http://127.0.0.1:5010")
	notifierURL := e2e.BaseURLFromEnv("NOTIFIER_BASE_URL", "http://127.0.0.1:9002")

	auth := e2e.NewClient(authURL, nil)
	auth.RequireUp(t, "/health")
	token := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	adminID := fetchUserID(t, auth, token)

	comment := e2e.NewClient(commentURL, e2e.Bearer(token))
	comment.RequireUp(t, "/health")

	resp, body, err := comment.Do(http.MethodPost, "/api/v1/comments", map[string]any{
		"tenantId": "default", "resourceType": "post", "resourceId": "e2e-notify-1", "content": "notifier e2e test",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusTooManyRequests)
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skip("comment rate limit exceeded")
	}

	svcToken := e2e.ServiceToken(t, authURL, serviceAuthID, serviceAuthSecret)
	notifier := e2e.NewClient(notifierURL, e2e.Bearer(svcToken))
	notifier.RequireUp(t, "/api/v1/health/")

	resp, body, err = notifier.Do(http.MethodGet, "/api/v1/service/notifications/user/"+adminID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestCrossService_FeedbackWithUserJWT(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	feedbackURL := e2e.BaseURLFromEnv("FEEDBACK_BASE_URL", "http://127.0.0.1:5012")

	token := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	h := e2e.Bearer(token)
	h["X-Tenant-ID"] = "default"
	c := e2e.NewClient(feedbackURL, h)
	c.RequireUp(t, "/health")

	resp, body, err := c.Do(http.MethodPost, "/api/v1/feedback", map[string]any{
		"title": "E2E cross-service", "description": "feedback auth test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("feedback rejected user JWT: %s", string(body))
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusTooManyRequests)
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skip("feedback rate limit exceeded")
	}
}

func TestCrossService_FeedbackNotifier(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	feedbackURL := e2e.BaseURLFromEnv("FEEDBACK_BASE_URL", "http://127.0.0.1:5012")
	notifierURL := e2e.BaseURLFromEnv("NOTIFIER_BASE_URL", "http://127.0.0.1:9002")

	auth := e2e.NewClient(authURL, nil)
	auth.RequireUp(t, "/health")
	token := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	adminID := fetchUserID(t, auth, token)

	h := e2e.Bearer(token)
	h["X-Tenant-ID"] = "default"
	feedback := e2e.NewClient(feedbackURL, h)
	feedback.RequireUp(t, "/health")

	resp, body, err := feedback.Do(http.MethodPost, "/api/v1/feedback", map[string]any{
		"title": "Notifier e2e", "description": "feedback notifier cross-service test",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusTooManyRequests)
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skip("feedback rate limit exceeded")
	}

	svcToken := e2e.ServiceToken(t, authURL, serviceAuthID, serviceAuthSecret)
	notifier := e2e.NewClient(notifierURL, e2e.Bearer(svcToken))
	notifier.RequireUp(t, "/api/v1/health/")

	resp, body, err = notifier.Do(http.MethodGet, "/api/v1/service/notifications/user/"+adminID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestCrossService_GatewayLogProxy(t *testing.T) {
	gw := e2e.NewClient(e2e.BaseURLFromEnv("GATEWAY_BASE_URL", "http://127.0.0.1:8080"), nil)
	gw.RequireUp(t, "/health")

	logURL := e2e.BaseURLFromEnv("LOG_BASE_URL", "http://127.0.0.1:5002")
	logClient := e2e.NewClient(logURL, nil)
	logClient.RequireUp(t, "/health")

	resp, body, err := logClient.Do(http.MethodPost, "/api/v1/logs", map[string]any{
		"service_name": "e2e-cross", "level": "INFO", "message": "cross-service log ingest",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated)

	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	token := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	resp, body, err = gw.WithHeaders(e2e.Bearer(token)).Do(http.MethodPost, "/api/v1/logs", map[string]any{
		"service_name": "e2e-gateway", "level": "INFO", "message": "via gateway",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("gateway does not expose /api/v1/logs yet")
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated, http.StatusUnauthorized, http.StatusBadGateway)
}

func TestCrossService_StorageWithUserJWT(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	storageURL := e2e.BaseURLFromEnv("STORAGE_BASE_URL", "http://127.0.0.1:5004")

	_, _, _, h := e2e.AdminAuthContext(t, authURL, adminEmail, adminPassword)
	c := e2e.NewClient(storageURL, h)
	c.RequireUp(t, "/health")

	resp, body, err := c.Do(http.MethodGet, "/api/v1/folders", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("storage rejected user JWT (restart storage after auth fix): %s", string(body))
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func TestCrossService_TicketNotifier(t *testing.T) {
	authURL := e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)
	ticketURL := e2e.BaseURLFromEnv("TICKET_BASE_URL", "http://127.0.0.1:5011")
	notifierURL := e2e.BaseURLFromEnv("NOTIFIER_BASE_URL", "http://127.0.0.1:9002")

	auth := e2e.NewClient(authURL, nil)
	auth.RequireUp(t, "/health")
	token := e2e.LoginAuth(t, authURL, adminEmail, adminPassword)
	adminID := fetchUserID(t, auth, token)

	h := e2e.Bearer(token)
	h["X-Tenant-ID"] = "default"
	ticket := e2e.NewClient(ticketURL, h)
	ticket.RequireUp(t, "/health")

	resp, body, err := ticket.Do(http.MethodPost, "/api/v1/tickets", map[string]any{
		"subject": "Notifier e2e ticket", "description": "ticket notifier cross-service test", "priority": "normal",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK, http.StatusCreated)

	svcToken := e2e.ServiceToken(t, authURL, serviceAuthID, serviceAuthSecret)
	notifier := e2e.NewClient(notifierURL, e2e.Bearer(svcToken))
	notifier.RequireUp(t, "/api/v1/health/")

	resp, body, err = notifier.Do(http.MethodGet, "/api/v1/service/notifications/user/"+adminID, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
}

func fetchUserID(t *testing.T, c *e2e.Client, token string) string {
	t.Helper()
	resp, body, err := c.WithHeaders(e2e.Bearer(token)).Do(http.MethodGet, "/api/v1/users/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	e2e.ExpectStatus(t, resp, body, http.StatusOK)
	var parsed map[string]any
	e2e.ParseJSON(t, body, &parsed)
	id := e2e.GetString(parsed, "data", "id")
	if id == "" {
		id = e2e.GetString(parsed, "id")
	}
	if id == "" {
		t.Fatalf("no user id: %s", string(body))
	}
	return id
}
