package service

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
)

// SettingsService loads and caches settings from database
type SettingsService struct {
	repo      repository.SettingRepository
	redis     *redis.Client
	logger    logging.Logger
	envConfig *config.Config // Fallback to env config

	cache     map[string]string
	cacheMu   sync.RWMutex
	cacheTime time.Time
	cacheTTL  time.Duration
}

func NewSettingsService(cfg *config.Config, repo repository.SettingRepository, rdb *redis.Client, logger logging.Logger) *SettingsService {
	return &SettingsService{
		repo:      repo,
		redis:     rdb,
		logger:    logger,
		envConfig: cfg,
		cache:     make(map[string]string),
		cacheTTL:  5 * time.Minute, // Refresh settings every 5 minutes
	}
}

// RefreshCache loads all settings from database into cache
func (s *SettingsService) RefreshCache(ctx context.Context) error {
	settings, err := s.repo.GetAll(ctx)
	if err != nil {
		s.logger.Error(logging.Postgres, logging.Select, "Failed to load settings", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return err
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.cache = make(map[string]string)
	for _, setting := range settings {
		s.cache[setting.Key] = setting.Value
	}
	s.cacheTime = time.Now()

	s.logger.Debug(logging.General, logging.Api, "Settings cache refreshed", map[logging.ExtraKey]interface{}{
		"count": len(settings),
	})

	return nil
}

func (s *SettingsService) isCacheValid() bool {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return time.Since(s.cacheTime) < s.cacheTTL
}

func (s *SettingsService) get(key string) (string, bool) {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	val, ok := s.cache[key]
	return val, ok
}

// GetString returns a string setting value
func (s *SettingsService) GetString(ctx context.Context, key, defaultValue string) string {
	if !s.isCacheValid() {
		s.RefreshCache(ctx)
	}
	if val, ok := s.get(key); ok {
		return val
	}
	return defaultValue
}

// GetInt returns an int setting value
func (s *SettingsService) GetInt(ctx context.Context, key string, defaultValue int) int {
	if !s.isCacheValid() {
		s.RefreshCache(ctx)
	}
	if val, ok := s.get(key); ok {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// GetBool returns a bool setting value
func (s *SettingsService) GetBool(ctx context.Context, key string, defaultValue bool) bool {
	if !s.isCacheValid() {
		s.RefreshCache(ctx)
	}
	if val, ok := s.get(key); ok {
		if boolVal, err := strconv.ParseBool(val); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// GetDuration returns a duration setting value (stored as minutes in DB)
func (s *SettingsService) GetDuration(ctx context.Context, key string, defaultValue time.Duration) time.Duration {
	if !s.isCacheValid() {
		s.RefreshCache(ctx)
	}
	if val, ok := s.get(key); ok {
		if minutes, err := strconv.Atoi(val); err == nil {
			return time.Duration(minutes) * time.Minute
		}
	}
	return defaultValue
}

// Settings getters with fallback to env config

// GetMaxLoginAttempts returns max login attempts from DB or env
func (s *SettingsService) GetMaxLoginAttempts(ctx context.Context) int {
	return s.GetInt(ctx, models.SettingKeyMaxLoginAttempts, 5)
}

// GetLockDuration returns account lock duration from DB or env
func (s *SettingsService) GetLockDuration(ctx context.Context) time.Duration {
	return s.GetDuration(ctx, models.SettingKeyLockDuration, 30*time.Minute)
}

// GetOTPLength returns OTP length from DB or env
func (s *SettingsService) GetOTPLength(ctx context.Context) int {
	dbVal := s.GetInt(ctx, models.SettingKeyOTPLength, 0)
	if dbVal > 0 {
		return dbVal
	}
	return s.envConfig.OTP.Length
}

// GetOTPExpiry returns OTP expiry from DB or env
func (s *SettingsService) GetOTPExpiry(ctx context.Context) time.Duration {
	dbVal := s.GetDuration(ctx, models.SettingKeyOTPExpiry, 0)
	if dbVal > 0 {
		return dbVal
	}
	return s.envConfig.OTP.Expiry
}

// IsRegistrationAllowed checks if registration is enabled
func (s *SettingsService) IsRegistrationAllowed(ctx context.Context) bool {
	return s.GetBool(ctx, models.SettingKeyAllowRegistration, true)
}

// IsEmailVerificationRequired checks if email verification is required
func (s *SettingsService) IsEmailVerificationRequired(ctx context.Context) bool {
	return s.GetBool(ctx, models.SettingKeyRequireEmailVerify, false)
}

// IsPhoneVerificationRequired checks if phone verification is required
func (s *SettingsService) IsPhoneVerificationRequired(ctx context.Context) bool {
	return s.GetBool(ctx, models.SettingKeyRequirePhoneVerify, false)
}

// IsGoogleLoginEnabled checks if Google OAuth is enabled
func (s *SettingsService) IsGoogleLoginEnabled(ctx context.Context) bool {
	return s.GetBool(ctx, models.SettingKeyEnableGoogleLogin, true) && s.envConfig.Google.ClientID != ""
}

// IsOTPLoginEnabled checks if OTP login is enabled
func (s *SettingsService) IsOTPLoginEnabled(ctx context.Context) bool {
	return s.GetBool(ctx, models.SettingKeyEnableOTPLogin, true)
}

// GetGoogleOAuthConfig returns Google OAuth config (from env, IDs from DB if set)
func (s *SettingsService) GetGoogleOAuthConfig(ctx context.Context) config.GoogleOAuthConfig {
	cfg := s.envConfig.Google

	// Override with DB values if set
	if clientID := s.GetString(ctx, "google_client_id", ""); clientID != "" {
		cfg.ClientID = clientID
	}
	if clientSecret := s.GetString(ctx, "google_client_secret", ""); clientSecret != "" {
		cfg.ClientSecret = clientSecret
	}
	if redirectURL := s.GetString(ctx, "google_redirect_url", ""); redirectURL != "" {
		cfg.RedirectURL = redirectURL
	}

	return cfg
}

// GetGoogleClientID returns Google OAuth client ID from DB or env
func (s *SettingsService) GetGoogleClientID(ctx context.Context) string {
	if clientID := s.GetString(ctx, "google_client_id", ""); clientID != "" {
		return clientID
	}
	return s.envConfig.Google.ClientID
}

// GetGoogleClientSecret returns Google OAuth client secret from DB or env
func (s *SettingsService) GetGoogleClientSecret(ctx context.Context) string {
	if clientSecret := s.GetString(ctx, "google_client_secret", ""); clientSecret != "" {
		return clientSecret
	}
	return s.envConfig.Google.ClientSecret
}

// Set updates a setting in the database
func (s *SettingsService) Set(ctx context.Context, key, value string) error {
	err := s.repo.Set(ctx, key, value)
	if err != nil {
		return err
	}
	// Update cache
	s.cacheMu.Lock()
	s.cache[key] = value
	s.cacheMu.Unlock()
	return nil
}
