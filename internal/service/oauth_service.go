package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	clientID := s.settingsService.GetGoogleClientID(context.Background())
	if clientID == "" {
		return "", ErrOAuthNotConfigured
	}

	baseURL := "https://accounts.google.com/o/oauth2/v2/auth"

	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", s.cfg.Google.RedirectURL)
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
	clientID := s.settingsService.GetGoogleClientID(ctx)
	clientSecret := s.settingsService.GetGoogleClientSecret(ctx)

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", s.cfg.Google.RedirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
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
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
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
			Phone:         user.Phone,
			Avatar:        user.Avatar,
			EmailVerified: user.EmailVerified,
			PhoneVerified: user.PhoneVerified,
			Roles:         roles,
		},
	}, nil
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
