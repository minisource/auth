package service

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
)

// ServiceTokenClaims represents claims for service-to-service JWT
type ServiceTokenClaims struct {
	ClientID string   `json:"clientId"`
	TenantID string   `json:"tenantId,omitempty"` // Tenant context for service
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	Type     string   `json:"type"` // "service"
	jwt.RegisteredClaims
}

// ServiceAuthService handles service-to-service authentication
type ServiceAuthService struct {
	cfg               *config.JWTConfig
	serviceClientRepo repository.ServiceClientRepository
	passwordService   *PasswordService
	logger            logging.Logger
}

func NewServiceAuthService(
	cfg *config.JWTConfig,
	serviceClientRepo repository.ServiceClientRepository,
	passwordService *PasswordService,
	logger logging.Logger,
) *ServiceAuthService {
	return &ServiceAuthService{
		cfg:               cfg,
		serviceClientRepo: serviceClientRepo,
		passwordService:   passwordService,
		logger:            logger,
	}
}

// AuthenticateService authenticates a service client and returns a JWT
func (s *ServiceAuthService) AuthenticateService(ctx context.Context, clientID, clientSecret string) (string, time.Time, error) {
	// Get service client
	client, err := s.serviceClientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.logger.Error(logging.Postgres, logging.Select, "Failed to get service client", map[logging.ExtraKey]interface{}{
			"error":    err.Error(),
			"clientId": clientID,
		})
		return "", time.Time{}, err
	}

	if client == nil {
		s.logger.Debug(logging.General, logging.Api, "Service client not found", map[logging.ExtraKey]interface{}{
			"clientId": clientID,
		})
		return "", time.Time{}, ErrInvalidCredentials
	}

	// Check if active
	if !client.IsValid() {
		s.logger.Debug(logging.General, logging.Api, "Service client is not valid", map[logging.ExtraKey]interface{}{
			"clientId": clientID,
			"isActive": client.IsActive,
		})
		return "", time.Time{}, ErrUserDisabled
	}

	// Verify secret
	if !s.passwordService.VerifyPassword(clientSecret, client.ClientSecret) {
		s.logger.Debug(logging.General, logging.Api, "Invalid client secret", map[logging.ExtraKey]interface{}{
			"clientId": clientID,
		})
		return "", time.Time{}, ErrInvalidCredentials
	}

	// Update last used
	if err := s.serviceClientRepo.UpdateLastUsed(ctx, client.ID); err != nil {
		s.logger.Debug(logging.Postgres, logging.Update, "Failed to update last used", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	// Generate service token
	token, expiresAt, err := s.GenerateServiceToken(client)
	if err != nil {
		return "", time.Time{}, err
	}

	// Cache token in Redis
	expiry := time.Until(expiresAt)
	if err := s.serviceClientRepo.CacheServiceToken(ctx, clientID, token, expiry); err != nil {
		s.logger.Debug(logging.Redis, logging.Api, "Failed to cache service token", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	s.logger.Info(logging.General, logging.Api, "Service authenticated successfully", map[logging.ExtraKey]interface{}{
		"clientId": clientID,
		"name":     client.Name,
	})

	return token, expiresAt, nil
}

// GenerateServiceToken creates a JWT for a service client
func (s *ServiceAuthService) GenerateServiceToken(client *models.ServiceClient) (string, time.Time, error) {
	now := time.Now()
	// Service tokens typically have longer expiry (1 hour)
	expiresAt := now.Add(1 * time.Hour)

	tenantIDStr := ""
	if client.TenantID != nil {
		tenantIDStr = client.TenantID.String()
	}

	claims := ServiceTokenClaims{
		ClientID: client.ClientID,
		TenantID: tenantIDStr,
		Name:     client.Name,
		Scopes:   client.GetScopesList(),
		Type:     "service",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   client.ID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.cfg.Secret))
	return tokenString, expiresAt, err
}

// ValidateServiceToken validates a service token
func (s *ServiceAuthService) ValidateServiceToken(ctx context.Context, tokenString string) (*ServiceTokenClaims, error) {
	// Check if blacklisted
	blacklisted, err := s.serviceClientRepo.IsTokenBlacklisted(ctx, tokenString)
	if err != nil {
		s.logger.Debug(logging.Redis, logging.Api, "Failed to check blacklist", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}
	if blacklisted {
		return nil, ErrTokenInvalid
	}

	token, err := jwt.ParseWithClaims(tokenString, &ServiceTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return []byte(s.cfg.Secret), nil
	})

	if err != nil {
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(*ServiceTokenClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	// Verify it's a service token
	if claims.Type != "service" {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

// GetCachedServiceToken gets cached token or generates new one
func (s *ServiceAuthService) GetCachedServiceToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	// Try to get cached token
	token, err := s.serviceClientRepo.GetCachedServiceToken(ctx, clientID)
	if err == nil && token != "" {
		// Validate token is still valid
		claims, err := s.ValidateServiceToken(ctx, token)
		if err == nil && claims != nil {
			return token, nil
		}
	}

	// Generate new token
	token, _, err = s.AuthenticateService(ctx, clientID, clientSecret)
	return token, err
}

// RevokeServiceToken revokes a service token
func (s *ServiceAuthService) RevokeServiceToken(ctx context.Context, clientID, token string) error {
	// Invalidate cached token
	if err := s.serviceClientRepo.InvalidateServiceToken(ctx, clientID); err != nil {
		s.logger.Debug(logging.Redis, logging.Api, "Failed to invalidate service token", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	// Blacklist the token
	return s.serviceClientRepo.BlacklistToken(ctx, token, 2*time.Hour)
}

// HasScope checks if a service token has a specific scope
func (s *ServiceAuthService) HasScope(claims *ServiceTokenClaims, requiredScope string) bool {
	for _, scope := range claims.Scopes {
		if scope == "*" || scope == requiredScope {
			return true
		}
	}
	return false
}

// CreateServiceClient creates a new service client
func (s *ServiceAuthService) CreateServiceClient(ctx context.Context, name, description string, scopes []string) (*models.ServiceClient, string, error) {
	// Generate client ID and secret
	clientID, err := GenerateSecureToken(32)
	if err != nil {
		return nil, "", err
	}

	rawSecret, err := GenerateSecureToken(64)
	if err != nil {
		return nil, "", err
	}

	hashedSecret, err := s.passwordService.HashPassword(rawSecret)
	if err != nil {
		return nil, "", err
	}

	client := &models.ServiceClient{
		Name:         name,
		ClientID:     clientID,
		ClientSecret: hashedSecret,
		Description:  description,
		Scopes:       joinScopes(scopes),
		IsActive:     true,
	}

	if err := s.serviceClientRepo.Create(ctx, client); err != nil {
		return nil, "", err
	}

	s.logger.Info(logging.Postgres, logging.Insert, "Service client created", map[logging.ExtraKey]interface{}{
		"name":     name,
		"clientId": clientID,
	})

	// Return raw secret (only shown once)
	return client, rawSecret, nil
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	result := scopes[0]
	for i := 1; i < len(scopes); i++ {
		result += "," + scopes[i]
	}
	return result
}
