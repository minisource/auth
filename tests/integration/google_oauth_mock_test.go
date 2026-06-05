package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestGoogleOAuthWithMockServer(t *testing.T) {
	base := os.Getenv("AUTH_BASE_URL")
	if base == "" {
		base = "http://127.0.0.1:9001"
	}
	mockBase := os.Getenv("MOCK_BASE_URL")
	if mockBase == "" {
		mockBase = "http://127.0.0.1:9191"
	}

	if _, err := http.Get(mockBase + "/health"); err != nil {
		t.Skipf("dev-mocks not running at %s: %v", mockBase, err)
	}

	resp, err := http.Get(base + "/api/v1/auth/google")
	if err != nil {
		t.Fatalf("get google auth url: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("google auth url status=%d body=%s", resp.StatusCode, body)
	}

	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if !strings.Contains(out.URL, "/mock/google/auth") {
		t.Fatalf("expected mock auth url, got %s", out.URL)
	}

	cbResp, err := http.Get(base + "/api/v1/auth/google/callback?code=mock-auth-code")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer cbResp.Body.Close()
	cbBody, _ := io.ReadAll(cbResp.Body)
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", cbResp.StatusCode, cbBody)
	}
	if !strings.Contains(string(cbBody), "accessToken") {
		t.Fatalf("expected tokens in callback response: %s", cbBody)
	}
}
