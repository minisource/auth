package auth

import (
	"encoding/json"
	"fmt"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/minisource/auth/service/models"
	"github.com/minisource/common_go/http/helper"
)

var authService *AuthService

type AuthService struct {
	CasdoorClient *casdoorsdk.Client
	APIClient     *helper.APIClient
	Application   string
	Organization  string
	ClientID      string
	ClientSecret  string
	Endpoint      string
	Certificate   string
}

type AuthServiceConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Certificate  string
	Organization string
	Application  string
}

func NewAuthService(config AuthServiceConfig) *AuthService {
	casdoor := casdoorsdk.NewClient(
		config.Endpoint,     // Casdoor server URL
		config.ClientID,     // Client ID
		config.ClientSecret, // Client Secret
		config.Certificate,  // JWT public key or certificate
		config.Organization, // Casdoor organization
		config.Application,  // Casdoor application
	)

	authService = &AuthService{
		CasdoorClient: casdoor,
		APIClient:     helper.NewAPIClient(config.Endpoint).SetBasicAuth(config.ClientID, config.ClientSecret),
		Application:   config.Application,
		Organization:  config.Organization,
		ClientID:      config.ClientID,
		ClientSecret:  config.ClientSecret,
		Endpoint:      config.Endpoint,
		Certificate:   config.Certificate,
	}
	return authService
}

func GetAuthService() *AuthService {
	return authService
}

func (s *AuthService) HealthCheck() error {
	resp := s.APIClient.Get("/api/health")

	if resp.Error != nil {
		return resp.Error
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("health check failed with status %d: %s",
			resp.StatusCode, string(resp.Body))
	}

	var healthResp models.HealthCheckResponse
	if err := json.Unmarshal(resp.Body, &healthResp); err != nil {
		return fmt.Errorf("failed to parse health check response: %v", err)
	}

	// Optional: Validate status
	if healthResp.Status != "ok" {
		return fmt.Errorf("health check status is not 'ok': %s", healthResp.Status)
	}

	return nil
}


// RegisterUser registers a new user with forbidden status
func (s *AuthService) RegisterUser(countryCode, phoneNumber string) (*casdoorsdk.User, error) {
	phone := countryCode + phoneNumber
	// Fetch the newly created user to get the ID
	existedUser, _ := s.CasdoorClient.GetUserByPhone(phone)
	if existedUser != nil {
		return existedUser, nil
	}

	// Create user with IsForbidden = true (inactive)
	user := &casdoorsdk.User{
		CountryCode: countryCode,
		Phone:       countryCode + phoneNumber,
		Name:        "user_" + phoneNumber,
	}
	success, err := s.CasdoorClient.AddUser(user)
	if err != nil || !success {
		return nil, err
	}

	user, err = s.CasdoorClient.GetUserByPhone(phone)
	if err != nil {
		return nil, err
	}

	return user, nil
}


// SendOTP generates and sends an OTP to the user's phone
func (s *AuthService) SendOTP(phone string) error {
	params := map[string]string{
		"dest":          phone,
		"method":        "login",
		"type":          "phone",
		"captchaType":   "none",
		"applicationId": "admin/" + s.Application,
	}
	response, err := s.CasdoorClient.DoPost("send-verification-code", params, nil, false, false)
	if err != nil {
		return err
	}
	fmt.Println("Verification code sent successfully:", response)
	return nil
}

// VerifyOTP verifies the OTP
func (s *AuthService) VerifyCode(phone, code string) (bool, error) {
	params := map[string]interface{}{
		"username": phone,
		"code":     code,
	}

	var response map[string]interface{}

	err := s.APIClient.PostJSON("/api/verify-code", params, &response)

	if err != nil {
		return false, fmt.Errorf("request failed: %v", err)
	}

	fmt.Println("Verification response:", response)

	if status, ok := response["status"].(string); ok && status == "ok" {
		return true, nil
	}

	return false, fmt.Errorf("verification failed: %v", response)
}

// GenerateJWT generates a JWT token for the user
func (s *AuthService) GenerateJWT(username string) (*models.AccessTokenResponse, error) {
	// Placeholder using Casdoor's token generation
	formData := map[string]string{
		"grant_type": "token",
		"username":   username,
		// "client_id":     s.ClientID,
		// "client_secret": s.ClientSecret,
	}
	resp := s.APIClient.Post("/api/login/oauth/access_token", formData)

	if resp.Error != nil {
		return nil, resp.Error
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token request failed with status %d: %s",
			resp.StatusCode, string(resp.Body))
	}

	var tokenResp models.AccessTokenResponse
	if err := json.Unmarshal(resp.Body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %v", err)
	}

	return &tokenResp, nil
}

func (s *AuthService) ValidateToken(accessToken string) (*casdoorsdk.IntrospectTokenResult, error) {
	// Introspect the token
	tokenInfo, err := s.CasdoorClient.IntrospectToken(accessToken, "access_token")
	if err != nil {
		return nil, fmt.Errorf("token introspection failed: %v", err)
	}

	if !tokenInfo.Active {
		return nil, fmt.Errorf("token is not active")
	}

	return tokenInfo, nil
}


func (s *AuthService) GetUserInfoByUsername(username string) (*casdoorsdk.User, error) {
	// Get user by username
	user, err := s.CasdoorClient.GetUser(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %v", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user '%s' not found", username)
	}

	return user, nil
}

func (s *AuthService) GetUserInfoByPhone(phoneNumber string) (*casdoorsdk.User, error) {
	// Get user by phone
	user, err := s.CasdoorClient.GetUserByPhone(phoneNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %v", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user '%s' not found", phoneNumber)
	}

	return user, nil
}
