package tests

import (
	"testing"

	auth "github.com/minisource/auth/service"
)

func newTestAuthService() *auth.AuthService {
	cfg := auth.AuthServiceConfig{
		Endpoint:     "http://localhost:8000",
		ClientID:     "d6b27974f7bcbf88fcde",
		ClientSecret: "ff6443c597f3a02052c2ce6007163bb921a352f3",
		Certificate:  "",
		Organization: "DiviPay",
		Application:  "DiviPay_app",
	}

	return auth.NewAuthService(cfg)
}

func TestHealthCheck(t *testing.T) {
	service := newTestAuthService()

	if err := service.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}

func TestSendOTP(t *testing.T) {
	service := newTestAuthService()

	testPhone := "+989011793041"

	err := service.SendOTP(testPhone)
	if err != nil {
		t.Fatalf("SendOTP failed: %v", err)
	}
}
