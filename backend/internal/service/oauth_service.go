package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
)

// GoogleUserInfo represents user info from Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// GoogleTokenResponse represents token response from Google
type GoogleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// OAuthService handles OAuth authentication
type OAuthService struct {
	cfg              *config.Config
	userRepo         repository.UserRepository
	oauthRepo        repository.OAuthAccountRepository
	roleRepo         repository.RoleRepository
	sessionRepo      repository.SessionRepository
	refreshTokenRepo repository.RefreshTokenRepository
	loginLogRepo     repository.LoginLogRepository
	tokenService     *TokenService
	settingsService  *SettingsService
	logger           logging.Logger
}

func NewOAuthService(
	cfg *config.Config,
	userRepo repository.UserRepository,
	oauthRepo repository.OAuthAccountRepository,
	roleRepo repository.RoleRepository,
	sessionRepo repository.SessionRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	loginLogRepo repository.LoginLogRepository,
	tokenService *TokenService,
	settingsService *SettingsService,
	logger logging.Logger,
) *OAuthService {
	return &OAuthService{
		cfg:              cfg,
		userRepo:         userRepo,
		oauthRepo:        oauthRepo,
		roleRepo:         roleRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		loginLogRepo:     loginLogRepo,
		tokenService:     tokenService,
		settingsService:  settingsService,
		logger:           logger,
	}
}

// GetGoogleAuthURL generates the Google OAuth URL for login
func (s *OAuthService) GetGoogleAuthURL(state string) (string, error) {
	googleCfg := s.settingsService.GetGoogleOAuthConfig(context.Background())
	clientID := googleCfg.ClientID
	if clientID == "" {
		return "", ErrOAuthNotConfigured
	}

	baseURL := googleCfg.AuthURL
	if baseURL == "" {
		baseURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}

	redirectURL := googleCfg.RedirectURL
	if redirectURL == "" {
		redirectURL = s.cfg.Google.RedirectURL
	}

	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURL)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")

	return fmt.Sprintf("%s?%s", baseURL, params.Encode()), nil
}

// HandleGoogleCallback processes Google OAuth callback
func (s *OAuthService) HandleGoogleCallback(ctx context.Context, code, ipAddress, userAgent string) (*AuthResponse, error) {
	// Exchange code for tokens
	tokenResp, err := s.exchangeGoogleCode(ctx, code)
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, "Failed to exchange Google code", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, ErrOAuthFailed
	}

	// Get user info from Google
	userInfo, err := s.getGoogleUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, "Failed to get Google user info", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, ErrOAuthFailed
	}

	// Find or create user
	user, err := s.findOrCreateOAuthUser(ctx, userInfo, tokenResp)
	if err != nil {
		return nil, err
	}

	// Create session
	return s.createOAuthSession(ctx, user, ipAddress, userAgent)
}

func (s *OAuthService) exchangeGoogleCode(ctx context.Context, code string) (*GoogleTokenResponse, error) {
	googleCfg := s.settingsService.GetGoogleOAuthConfig(ctx)
	clientID := googleCfg.ClientID
	clientSecret := googleCfg.ClientSecret
	redirectURL := googleCfg.RedirectURL
	if redirectURL == "" {
		redirectURL = s.cfg.Google.RedirectURL
	}
	tokenURL := googleCfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google token exchange failed: %s", string(body))
	}

	var tokenResp GoogleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (s *OAuthService) getGoogleUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	googleCfg := s.settingsService.GetGoogleOAuthConfig(ctx)
	userInfoURL := googleCfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo failed: %s", string(body))
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (s *OAuthService) findOrCreateOAuthUser(ctx context.Context, info *GoogleUserInfo, tokenResp *GoogleTokenResponse) (*models.User, error) {
	// Check if OAuth account exists
	oauthAccount, err := s.oauthRepo.GetByProviderID(ctx, models.OAuthProviderGoogle, info.ID)
	if err != nil {
		return nil, err
	}

	if oauthAccount != nil {
		// Update OAuth tokens
		oauthAccount.AccessToken = tokenResp.AccessToken
		if tokenResp.RefreshToken != "" {
			oauthAccount.RefreshToken = tokenResp.RefreshToken
		}
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		oauthAccount.ExpiresAt = &expiresAt
		s.oauthRepo.Update(ctx, oauthAccount)

		// Get user
		user, err := s.userRepo.GetByID(ctx, oauthAccount.UserID)
		if err != nil || user == nil {
			return nil, ErrUserNotFound
		}

		if !user.IsActive {
			return nil, ErrUserDisabled
		}

		return user, nil
	}

	// Check if user exists by email
	user, err := s.userRepo.GetByEmail(ctx, info.Email)
	if err != nil {
		return nil, err
	}

	if user != nil {
		// Link OAuth account to existing user
		if !user.IsActive {
			return nil, ErrUserDisabled
		}

		oauthAccount = &models.OAuthAccount{
			UserID:       user.ID,
			Provider:     models.OAuthProviderGoogle,
			ProviderID:   info.ID,
			Email:        info.Email,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ExpiresAt:    func() *time.Time { t := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second); return &t }(),
		}
		s.oauthRepo.Create(ctx, oauthAccount)

		// Update user info if not set
		if user.FirstName == "" {
			user.FirstName = info.GivenName
		}
		if user.LastName == "" {
			user.LastName = info.FamilyName
		}
		if user.Avatar == "" {
			user.Avatar = info.Picture
		}
		if !user.EmailVerified {
			user.EmailVerified = info.VerifiedEmail
		}
		s.userRepo.Update(ctx, user)

		return user, nil
	}

	// Create new user
	username := generateUsernameFromEmail(info.Email)

	// Check if username exists, append random suffix if needed
	exists, _ := s.userRepo.ExistsByUsername(ctx, username)
	if exists {
		username = username + "_" + uuid.New().String()[:4]
	}

	// Generate random password for OAuth user
	randomPass, _ := GenerateSecureToken(32)

	user = &models.User{
		Email:         info.Email,
		Username:      username,
		PasswordHash:  randomPass, // Not used for OAuth login
		FirstName:     info.GivenName,
		LastName:      info.FamilyName,
		Avatar:        info.Picture,
		EmailVerified: info.VerifiedEmail,
		IsActive:      true,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Assign default role
	defaultRole, _ := s.roleRepo.GetByName(ctx, models.RoleUser)
	if defaultRole != nil {
		s.userRepo.AssignRole(ctx, user.ID, defaultRole.ID)
	}

	// Create OAuth account
	oauthAccount = &models.OAuthAccount{
		UserID:       user.ID,
		Provider:     models.OAuthProviderGoogle,
		ProviderID:   info.ID,
		Email:        info.Email,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    func() *time.Time { t := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second); return &t }(),
	}
	s.oauthRepo.Create(ctx, oauthAccount)

	s.logger.Info(logging.General, logging.Api, "User created via Google OAuth", map[logging.ExtraKey]interface{}{
		"userId": user.ID,
		"email":  info.Email,
	})

	return user, nil
}

func (s *OAuthService) createOAuthSession(ctx context.Context, user *models.User, ipAddress, userAgent string) (*AuthResponse, error) {
	// Create session
	session := &models.Session{
		UserID:       user.ID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		IsActive:     true,
		ExpiresAt:    time.Now().Add(s.cfg.JWT.RefreshExpiry),
		LastActiveAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = ipAddress
	s.userRepo.Update(ctx, user)

	// Log login
	log := &models.LoginLog{
		UserID:    user.ID,
		SessionID: session.ID,
		Action:    models.LoginActionOAuthLogin,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
	}
	s.loginLogRepo.Create(ctx, log)

	// Get user with roles
	userWithRoles, _ := s.userRepo.GetWithRoles(ctx, user.ID)
	if userWithRoles != nil {
		user = userWithRoles
	}

	roles := extractRoleNames(user.Roles)
	permissions := extractPermissions(user.Roles)

	// Get tenant ID from user
	var tenantID *uuid.UUID = user.TenantID

	// Generate tokens with tenant context
	accessToken, err := s.tokenService.GenerateAccessToken(user, tenantID, roles, permissions, session.ID)
	if err != nil {
		return nil, err
	}

	refreshToken, expiresAt, err := s.tokenService.GenerateRefreshToken(user.ID, session.ID)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	rt := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		SessionID: session.ID,
		ExpiresAt: expiresAt,
	}
	s.refreshTokenRepo.Create(ctx, rt)

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.cfg.JWT.AccessExpiry),
		TokenType:    "Bearer",
		User: &UserInfo{
			ID:            user.ID.String(),
			Email:         user.Email,
			Username:      user.Username,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Phone:         derefPhone(user.Phone),
			Avatar:        user.Avatar,
			EmailVerified: user.EmailVerified,
			PhoneVerified: user.PhoneVerified,
			Roles:         roles,
		},
	}, nil
}

// GoogleIDTokenClaims represents the parsed claims from a verified Google ID token.
type GoogleIDTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	AtHash        string `json:"at_hash"`
}

// GoogleIDTokenInfo represents the parsed claims from a verified Google ID token.
type GoogleIDTokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// googleJWKS is the cached Google JSON Web Key Set.
type googleJWKSCache struct {
	mu     sync.RWMutex
	keys   map[string][]byte // kid → PEM certificate bytes
	expiry time.Time
}

var googleKeys = &googleJWKSCache{}

// Google JWKS endpoint
const googleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// fetchGoogleCerts fetches Google's public keys and caches them as PEM certificates.
func (s *OAuthService) fetchGoogleCerts(ctx context.Context) (map[string][]byte, error) {
	googleKeys.mu.RLock()
	if time.Now().Before(googleKeys.expiry) && len(googleKeys.keys) > 0 {
		keys := googleKeys.keys
		googleKeys.mu.RUnlock()
		return keys, nil
	}
	googleKeys.mu.RUnlock()

	googleKeys.mu.Lock()
	defer googleKeys.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(googleKeys.expiry) && len(googleKeys.keys) > 0 {
		return googleKeys.keys, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", googleCertsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google certs request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Google certs: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google certs: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google certs returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JWKS response: {"keys": [...]}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse Google certs: %w", err)
	}

	keys := make(map[string][]byte, len(jwks.Keys))
	for _, rawKey := range jwks.Keys {
		var keyData struct {
			Kid string   `json:"kid"`
			Use string   `json:"use"`
			Alg string   `json:"alg"`
			X5c []string `json:"x5c"`
		}
		if err := json.Unmarshal(rawKey, &keyData); err != nil {
			continue
		}

		// Convert x5c[0] (base64 DER) to PEM format for golang-jwt
		if len(keyData.X5c) == 0 {
			s.logger.Warn(logging.General, logging.ExternalService, "Google cert missing x5c",
				map[logging.ExtraKey]interface{}{"kid": keyData.Kid})
			continue
		}

		pemCert := derToPEM(keyData.X5c[0])
		keys[keyData.Kid] = pemCert
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in Google certs")
	}

	googleKeys.keys = keys
	googleKeys.expiry = time.Now().Add(5 * time.Minute)

	s.logger.Debug(logging.General, logging.ExternalService, "Fetched Google certs",
		map[logging.ExtraKey]interface{}{"keyCount": len(keys)})

	return keys, nil
}

// derToPEM converts a base64-encoded DER certificate to PEM format.
func derToPEM(base64DER string) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + base64DER + "\n-----END CERTIFICATE-----")
}

// VerifyGoogleIDToken verifies a Google ID token locally using Google's public keys (JWKS).
// Falls back to the deprecated tokeninfo endpoint if JWKS verification fails.
func (s *OAuthService) VerifyGoogleIDToken(ctx context.Context, idToken string) (*GoogleIDTokenInfo, error) {
	googleCfg := s.settingsService.GetGoogleOAuthConfig(ctx)

	// Attempt local verification first (production-ready, uses Google's JWKS)
	info, err := s.verifyIDTokenLocally(ctx, idToken, googleCfg.ClientID)
	if err == nil {
		return info, nil
	}

	// Log the local verification failure for debugging
	s.logger.Warn(logging.General, logging.ExternalService, "Local Google ID token verification failed, falling back to tokeninfo",
		map[logging.ExtraKey]interface{}{"error": err.Error()})
	fmt.Printf("\n=== JWKS LOCAL VERIFY FAILED (falling back to tokeninfo) ===\n%s\n==============================================================\n\n", err.Error())

	// Fall back to tokeninfo for backward compatibility
	return s.verifyIDTokenWithTokeninfo(ctx, idToken, googleCfg)
}

// verifyIDTokenLocally verifies a Google ID token using Google's public keys.
func (s *OAuthService) verifyIDTokenLocally(ctx context.Context, idToken, expectedAudience string) (*GoogleIDTokenInfo, error) {
	certs, err := s.fetchGoogleCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Google certs: %w", err)
	}

	var claims GoogleIDTokenClaims
	token, err := jwt.ParseWithClaims(idToken, &claims, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm (Google uses RS256 or ES256)
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}

		// Get the key ID from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Look up the key in the JWKS
		pemBytes, ok := certs[kid]
		if !ok {
			// Key might have been rotated; force a refresh
			googleKeys.mu.Lock()
			googleKeys.expiry = time.Time{} // force refresh next time
			googleKeys.mu.Unlock()
			return nil, fmt.Errorf("key %s not found in Google certs", kid)
		}

		// Parse the PEM certificate into a public key
		return jwt.ParseRSAPublicKeyFromPEM(pemBytes)
	})

	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Validate claims
	if err := claims.ValidateGoogleClaims(expectedAudience, s.cfg.IsProduction(), s.logger); err != nil {
		return nil, err
	}

	return &GoogleIDTokenInfo{
		Sub:           claims.Subject,
		Email:         claims.Email,
		VerifiedEmail: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
	}, nil
}

// ValidateGoogleClaims validates the standard Google ID token claims.
func (c *GoogleIDTokenClaims) ValidateGoogleClaims(expectedAudience string, isProd bool, logger logging.Logger) error {
	// Validate issuer
	validIssuers := []string{"accounts.google.com", "https://accounts.google.com"}
	issuerValid := false
	for _, issuer := range validIssuers {
		if c.Issuer == issuer {
			issuerValid = true
			break
		}
	}
	if !issuerValid {
		return fmt.Errorf("invalid issuer: %s", c.Issuer)
	}

	// Validate audience
	if expectedAudience != "" && c.Audience != nil {
		audMatch := false
		for _, aud := range c.Audience {
			if aud == expectedAudience {
				audMatch = true
				break
			}
		}
		if !audMatch {
			if isProd {
				return fmt.Errorf("audience mismatch: expected %s, got %v", expectedAudience, c.Audience)
			}
			// In dev, log but don't fail
			logger.Warn(logging.General, logging.Api, "Google ID token audience mismatch",
				map[logging.ExtraKey]interface{}{"aud": c.Audience, "expectedClientId": expectedAudience})
		}
	}

	// Validate expiry (jwt library does this automatically, but double-check)
	if c.ExpiresAt != nil && time.Now().After(c.ExpiresAt.Time) {
		return fmt.Errorf("token expired at %v", c.ExpiresAt.Time)
	}

	return nil
}

// verifyIDTokenWithTokeninfo is the legacy fallback using Google's tokeninfo endpoint.
func (s *OAuthService) verifyIDTokenWithTokeninfo(ctx context.Context, idToken string, googleCfg config.GoogleOAuthConfig) (*GoogleIDTokenInfo, error) {
	// Use Google's oauth2/v3/tokeninfo endpoint (no client secret required)
	verifyURL := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	req, err := http.NewRequestWithContext(ctx, "GET", verifyURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token verification request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google token verification failed: %s", string(body))
	}

	// Unmarshal into raw map first because tokeninfo returns email_verified as
	// a string "true"/"false" instead of a boolean (known Google API inconsistency).
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	// Parse email_verified flexibly (string or bool)
	emailVerified := false
	switch v := raw["email_verified"].(type) {
	case bool:
		emailVerified = v
	case string:
		emailVerified = v == "true"
	}

	info := &GoogleIDTokenInfo{
		Sub:           getStringField(raw, "sub"),
		Email:         getStringField(raw, "email"),
		VerifiedEmail: emailVerified,
		Name:          getStringField(raw, "name"),
		GivenName:     getStringField(raw, "given_name"),
		FamilyName:    getStringField(raw, "family_name"),
		Picture:       getStringField(raw, "picture"),
	}

	// Verify the token was issued for our client (audience check)
	if aud, ok := raw["aud"]; ok {
		audStr := fmt.Sprintf("%v", aud)
		if audStr != googleCfg.ClientID {
			s.logger.Warn(logging.General, logging.Api, "Google ID token audience mismatch",
				map[logging.ExtraKey]interface{}{"aud": audStr, "clientId": googleCfg.ClientID})
			if s.cfg.IsProduction() {
				return nil, ErrOAuthFailed
			}
		}
	}

	return info, nil
}

// getStringField safely extracts a string field from a tokeninfo response map.
func getStringField(raw map[string]interface{}, key string) string {
	if v, ok := raw[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// HandleGoogleMobileLogin processes a Google ID token from mobile app.
// It verifies the token, finds or creates a user, and returns application tokens.
func (s *OAuthService) HandleGoogleMobileLogin(
	ctx context.Context,
	idToken, accessToken, displayName, email, photoURL, ipAddress, userAgent string,
) (*AuthResponse, error) {
	// Verify the ID token with Google
	info, err := s.VerifyGoogleIDToken(ctx, idToken)
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, "Failed to verify Google ID token",
			map[logging.ExtraKey]interface{}{"error": err.Error()})
		fmt.Printf("\n=== GOOGLE MOBILE LOGIN ERROR ===\n%s\n===================================\n\n", err.Error())
		return nil, ErrOAuthFailed
	}

	// Use mobile-provided values as fallback if token info is incomplete
	if info.Name == "" && displayName != "" {
		info.Name = displayName
	}
	if info.Email == "" && email != "" {
		info.Email = email
	}
	if info.Picture == "" && photoURL != "" {
		info.Picture = photoURL
	}

	// Build a GoogleUserInfo for the existing findOrCreateOAuthUser flow
	userInfo := &GoogleUserInfo{
		ID:            info.Sub,
		Email:         info.Email,
		VerifiedEmail: info.VerifiedEmail,
		Name:          info.Name,
		GivenName:     info.GivenName,
		FamilyName:    info.FamilyName,
		Picture:       info.Picture,
	}

	// Build a minimal token response (access token from mobile, no refresh token from Google)
	tokenResp := &GoogleTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   3600, // Mobile access tokens typically last 1 hour
	}

	// Find or create user
	user, err := s.findOrCreateOAuthUser(ctx, userInfo, tokenResp)
	if err != nil {
		return nil, err
	}

	// Create session
	return s.createOAuthSession(ctx, user, ipAddress, userAgent)
}

// UnlinkGoogleAccount removes Google OAuth link from user account
func (s *OAuthService) UnlinkGoogleAccount(ctx context.Context, userID uuid.UUID) error {
	// Check if user has password set
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrUserNotFound
	}

	// If user only has OAuth login, don't allow unlinking
	if user.PasswordHash == "" || len(user.PasswordHash) < 20 {
		return ErrOAuthUnlinkFailed
	}

	return s.oauthRepo.DeleteByUserAndProvider(ctx, userID, models.OAuthProviderGoogle)
}

// GetLinkedAccounts returns OAuth accounts linked to user
func (s *OAuthService) GetLinkedAccounts(ctx context.Context, userID uuid.UUID) ([]models.OAuthAccount, error) {
	return s.oauthRepo.GetByUserID(ctx, userID)
}
