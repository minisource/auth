package tests

import (
	"testing"

	auth "github.com/minisource/auth/service"
)

var phoneNumber = "+989011793041"

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

func TestRegisterUser(t *testing.T) {
	service := newTestAuthService()

	countryCode := "+98"

	user, err := service.RegisterUser(countryCode, phoneNumber)
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}

	if user == nil {
		t.Fatal("RegisterUser returned nil user")
	}

	if user.Phone != countryCode+phoneNumber {
		t.Fatalf("Unexpected phone in returned user: got %s, want %s", user.Phone, countryCode+phoneNumber)
	}

	t.Logf("User registered successfully: %s", user.Name)
}

func TestSendOTP(t *testing.T) {
	service := newTestAuthService()

	err := service.SendOTP(phoneNumber)
	if err != nil {
		t.Fatalf("SendOTP failed: %v", err)
	}
}

func TestVerifyCode(t *testing.T) {
	service := newTestAuthService()
	code := "951606"

	ok, err := service.VerifyCode(phoneNumber, code)
	if err != nil {
		t.Fatalf("VerifyCode failed: %v", err)
	}

	if !ok {
		t.Fatal("Verification failed: OTP is invalid")
	}

	t.Log("OTP verified successfully")
}

func TestGenerateJWT(t *testing.T) {
	service := newTestAuthService()

	token, err := service.GenerateJWT(phoneNumber)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	if token == nil || token.AccessToken == "" {
		t.Fatal("JWT token is nil or empty")
	}

	t.Logf("Access token: %s", token.AccessToken)
}

func TestGenerateServiceJWT(t *testing.T) {
	service := newTestAuthService()

	token, err := service.GenerateServiceJWT()
	if err != nil {
		t.Fatalf("GenerateServiceJWT failed: %v", err)
	}

	if token == nil {
		t.Fatal("JWT token is nil or empty")
	}

	t.Logf("Access token: %s", *token)
}

func TestValidateToken(t *testing.T) {
	service := newTestAuthService()

	tokenResp, err := service.GenerateJWT(phoneNumber)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	result, err := service.ValidateToken(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if result == nil || !result.Active {
		t.Fatal("Token is not active or result is nil")
	}

	t.Logf("Token is valid. Subject: %s, Scope: %s", result.Username, result.Sub)
}

func TestGetUserInfoByUsername(t *testing.T) {
	service := newTestAuthService()

	user, err := service.GetUserInfoByUsername("user_9011793041")
	if err != nil {
		t.Fatalf("GetUserInfoByUsername failed: %v", err)
	}

	if user == nil {
		t.Fatal("Returned user is nil")
	}

	t.Logf("User info retrieved: %s (%s)", user.Name, user.Id)
}

func TestGetUserInfoByPhone(t *testing.T) {
	service := newTestAuthService()

	user, err := service.GetUserInfoByPhone("+989011793041")
	if err != nil {
		t.Fatalf("GetUserInfoByPhone failed: %v", err)
	}

	if user == nil {
		t.Fatal("Returned user is nil")
	}

	t.Logf("User info retrieved by phone: %s (%s)", user.Name, user.Id)
}
