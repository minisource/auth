//go:build e2e

package e2e_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/minisource/go-common/testing/e2e"
)

func TestAuth_SwaggerRouteSmoke(t *testing.T) {
	c := authClient(t)
	_, file, _, _ := runtime.Caller(0)
	doc := filepath.Join(filepath.Dir(file), "..", "..", "docs", "swagger.json")
	token := e2e.LoginAuth(t, c.BaseURL, adminEmail, adminPassword)
	e2e.RunSwaggerSmoke(t, c, doc, e2e.Bearer(token), false)
}
