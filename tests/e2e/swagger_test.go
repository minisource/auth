//go:build e2e

package e2e_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/minisource/go-common/testing/e2e"
)

func TestSwagger_AllMiniServices(t *testing.T) {
	services := []struct {
		name string
		base string
	}{
		{"auth", e2e.BaseURLFromEnv("AUTH_BASE_URL", defaultAuthURL)},
		{"notifier", e2e.BaseURLFromEnv("NOTIFIER_BASE_URL", "http://127.0.0.1:9002")},
		{"gateway", e2e.BaseURLFromEnv("GATEWAY_BASE_URL", "http://127.0.0.1:8080")},
		{"log", e2e.BaseURLFromEnv("LOG_BASE_URL", "http://127.0.0.1:5002")},
		{"scheduler", e2e.BaseURLFromEnv("SCHEDULER_BASE_URL", "http://127.0.0.1:5003")},
		{"storage", e2e.BaseURLFromEnv("STORAGE_BASE_URL", "http://127.0.0.1:5004")},
		{"comment", e2e.BaseURLFromEnv("COMMENT_BASE_URL", "http://127.0.0.1:5010")},
		{"ticket", e2e.BaseURLFromEnv("TICKET_BASE_URL", "http://127.0.0.1:5011")},
		{"feedback", e2e.BaseURLFromEnv("FEEDBACK_BASE_URL", "http://127.0.0.1:5012")},
	}

	paymentBase := e2e.BaseURLFromEnv("PAYMENT_BASE_URL", "http://127.0.0.1:4005")
	if resp, _, err := e2e.NewClient(paymentBase, nil).Do(http.MethodGet, "/health", nil); err == nil && resp != nil && resp.StatusCode == http.StatusOK {
		services = append(services, struct {
			name string
			base string
		}{"payment", paymentBase})
	}

	for _, svc := range services {
		svc := svc
		t.Run(svc.name, func(t *testing.T) {
			c := e2e.NewClient(svc.base, nil)
			c.RequireUp(t, "/health")

			resp, body, err := c.Do(http.MethodGet, "/swagger/index.html", nil)
			if err != nil {
				t.Fatal(err)
			}
			e2e.ExpectStatus(t, resp, body, http.StatusOK)

			docPath := "/swagger/doc.json"
			if svc.name == "payment" {
				docPath = "/swagger/v1/swagger.json"
			}
			resp, body, err = c.Do(http.MethodGet, docPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			e2e.ExpectStatus(t, resp, body, http.StatusOK)

			var spec struct {
				Paths map[string]any `json:"paths"`
			}
			if err := json.Unmarshal(body, &spec); err != nil {
				t.Fatal(err)
			}
			if len(spec.Paths) == 0 {
				t.Fatalf("swagger doc has no paths for %s", svc.name)
			}
		})
	}
}
