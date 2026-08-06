package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/database"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
)

// webAuthnUser adapts a models.User (plus its passkeys) to the go-webauthn
// User interface.
type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                       { return u.id }
func (u *webAuthnUser) WebAuthnName() string                     { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string              { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// webAuthnSessionPurpose marks what ceremony a stored challenge belongs to so a
// login challenge can never be replayed against the registration endpoint (and
// vice versa).
type webAuthnSessionPurpose string

const (
	webAuthnPurposeRegister webAuthnSessionPurpose = "register"
	webAuthnPurposeLogin    webAuthnSessionPurpose = "login"
)

// WebAuthnService implements WebAuthn/passkey registration and login.
type WebAuthnService struct {
	cfg         *config.Config
	wa          *webauthn.WebAuthn
	passkeyRepo repository.PasskeyRepository
	userRepo    repository.UserRepository
	authService *AuthService
	rdb         *redis.Client
	ttl         time.Duration
	logger      logging.Logger
}

type storedWebAuthnSession struct {
	Purpose webAuthnSessionPurpose `json:"purpose"`
	webauthn.SessionData
}

// NewWebAuthnService creates the WebAuthnService and initializes the relying
// party from configuration. The service is disabled when WEBAUTHN_ENABLED=false
// (passkey endpoints then return a 503).
func NewWebAuthnService(cfg *config.Config, passkeyRepo repository.PasskeyRepository, userRepo repository.UserRepository, authService *AuthService, rdb *redis.Client, logger logging.Logger) (*WebAuthnService, error) {
	ttl := 5 * time.Minute
	if d, err := time.ParseDuration(cfg.WebAuthn.ChallengeTTL); err == nil && d > 0 {
		ttl = d
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthn.RPID,
		RPDisplayName: cfg.WebAuthn.RPName,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: init relying party: %w", err)
	}

	return &WebAuthnService{
		cfg:         cfg,
		wa:          wa,
		passkeyRepo: passkeyRepo,
		userRepo:    userRepo,
		authService: authService,
		rdb:         rdb,
		ttl:         ttl,
		logger:      logger,
	}, nil
}

// IsEnabled reports whether passkeys are enabled.
func (s *WebAuthnService) IsEnabled() bool {
	return s.cfg.WebAuthn.Enabled
}

// PasskeyInfo is the public representation of a registered passkey.
type PasskeyInfo struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	AAGUID    string  `json:"aaguid,omitempty"`
	Backup    bool    `json:"backup"`
	CreatedAt string  `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
}

// ─── Registration (authenticated) ─────────────────────────

// BeginRegistration starts a passkey registration ceremony for the user and
// returns the CredentialCreation options the browser needs.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, error) {
	if !s.IsEnabled() {
		return nil, ErrWebAuthnFailed
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	wu, err := s.webauthnUserFor(ctx, user)
	if err != nil {
		return nil, err
	}

	creation, sessionData, err := s.wa.BeginRegistration(
		wu,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		s.logger.Error(logging.General, logging.Api, "webauthn: begin registration failed", map[logging.ExtraKey]interface{}{
			"error":  err.Error(),
			"userId": userID,
		})
		return nil, ErrWebAuthnFailed
	}

	if err := s.saveSession(ctx, webAuthnPurposeRegister, sessionData); err != nil {
		return nil, err
	}

	return creation, nil
}

// FinishRegistration validates the authenticator response and persists the new
// passkey for the user.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID uuid.UUID, name string, rawBody []byte) (*PasskeyInfo, error) {
	if !s.IsEnabled() {
		return nil, ErrWebAuthnFailed
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(rawBody)
	if err != nil {
		return nil, ErrWebAuthnChallenge
	}

	challenge := parsed.Response.CollectedClientData.Challenge
	stored, err := s.loadAndDeleteSession(ctx, challenge)
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.Purpose != webAuthnPurposeRegister {
		return nil, ErrWebAuthnChallenge
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	wu, err := s.webauthnUserFor(ctx, user)
	if err != nil {
		return nil, err
	}

	cred, err := s.wa.CreateCredential(wu, stored.SessionData, parsed)
	if err != nil {
		s.logger.Warn(logging.General, logging.Api, "webauthn: finish registration rejected", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, ErrWebAuthnChallenge
	}

	// Reject duplicate credentials
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	existing, _ := s.passkeyRepo.GetByCredentialID(ctx, credID)
	if existing != nil {
		return nil, ErrPasskeyExists
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}

	passkey := &models.Passkey{
		UserID:         userID,
		Name:           sanitizePasskeyName(name, user),
		CredentialID:   credID,
		CredentialJSON: string(credJSON),
		AAGUID:         base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID),
		SignCount:      cred.Authenticator.SignCount,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}
	if err := s.passkeyRepo.Create(ctx, passkey); err != nil {
		return nil, err
	}

	s.logger.Info(logging.General, logging.Api, "passkey registered", map[logging.ExtraKey]interface{}{
		"userId": userID,
		"name":   passkey.Name,
	})
	info := toPasskeyInfo(passkey)
	return &info, nil
}

// ListPasskeys returns all passkeys for a user.
func (s *WebAuthnService) ListPasskeys(ctx context.Context, userID uuid.UUID) ([]PasskeyInfo, error) {
	passkeys, err := s.passkeyRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]PasskeyInfo, 0, len(passkeys))
	for _, pk := range passkeys {
		result = append(result, toPasskeyInfo(&pk))
	}
	return result, nil
}

// DeletePasskey removes a passkey belonging to the user.
func (s *WebAuthnService) DeletePasskey(ctx context.Context, userID, passkeyID uuid.UUID) error {
	pk, err := s.passkeyRepo.GetByID(ctx, passkeyID)
	if err != nil {
		return err
	}
	if pk == nil || pk.UserID != userID {
		return ErrPasskeyNotFound
	}
	if err := s.passkeyRepo.Delete(ctx, passkeyID); err != nil {
		return err
	}
	s.logger.Info(logging.General, logging.Api, "passkey deleted", map[logging.ExtraKey]interface{}{
		"userId": userID,
		"name":   pk.Name,
	})
	return nil
}

// ─── Login (public) ───────────────────────────────────────

// BeginLogin starts a passkey login ceremony for the account with the given
// email and returns the assertion options the browser needs.
func (s *WebAuthnService) BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, error) {
	if !s.IsEnabled() {
		return nil, ErrWebAuthnFailed
	}
	user, err := s.userRepo.GetByEmail(ctx, NormalizeEmail(email))
	if err != nil {
		return nil, err
	}

	// Return the same error for unknown accounts and accounts without passkeys
	// so the endpoint does not leak whether an email address is registered.
	if user == nil {
		return nil, ErrNoPasskeys
	}

	passkeys, err := s.passkeyRepo.GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if len(passkeys) == 0 {
		return nil, ErrNoPasskeys
	}

	wu, err := s.webauthnUserFor(ctx, user)
	if err != nil {
		return nil, err
	}

	assertion, sessionData, err := s.wa.BeginLogin(wu)
	if err != nil {
		s.logger.Error(logging.General, logging.Api, "webauthn: begin login failed", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, ErrWebAuthnFailed
	}

	if err := s.saveSession(ctx, webAuthnPurposeLogin, sessionData); err != nil {
		return nil, err
	}
	return assertion, nil
}

// FinishLogin validates the assertion and creates a full authenticated session.
func (s *WebAuthnService) FinishLogin(ctx context.Context, rawBody []byte, ipAddress, userAgent string) (*AuthResponse, error) {
	if !s.IsEnabled() {
		return nil, ErrWebAuthnFailed
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(rawBody)
	if err != nil {
		return nil, ErrWebAuthnChallenge
	}

	challenge := parsed.Response.CollectedClientData.Challenge
	stored, err := s.loadAndDeleteSession(ctx, challenge)
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.Purpose != webAuthnPurposeLogin {
		return nil, ErrWebAuthnChallenge
	}

	userID, err := uuid.FromBytes(stored.UserID)
	if err != nil {
		return nil, ErrWebAuthnChallenge
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}
	if !user.IsActive {
		return nil, ErrUserDisabled
	}
	if user.IsLocked() {
		s.authService.logLoginAttempt(ctx, user.ID, uuid.Nil, models.LoginActionLoginFailed, ipAddress, userAgent, false, "user locked")
		return nil, ErrUserLocked
	}

	wu, err := s.webauthnUserFor(ctx, user)
	if err != nil {
		return nil, err
	}

	cred, err := s.wa.ValidateLogin(wu, stored.SessionData, parsed)
	if err != nil {
		s.logger.Warn(logging.General, logging.Api, "webauthn: login rejected", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		s.authService.handleFailedLogin(ctx, user, ipAddress, userAgent)
		return nil, ErrWebAuthnChallenge
	}

	// Update sign count + last-used on the matched passkey.
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if pk, err := s.passkeyRepo.GetByCredentialID(ctx, credID); err == nil && pk != nil {
		now := time.Now()
		pk.SignCount = cred.Authenticator.SignCount
		pk.LastUsedAt = &now
		if credJSON, err := json.Marshal(cred); err == nil {
			pk.CredentialJSON = string(credJSON)
		}
		_ = s.passkeyRepo.Update(ctx, pk)
	}

	return s.authService.CreatePasskeySession(ctx, user, ipAddress, userAgent)
}

// ─── Helpers ──────────────────────────────────────────────

func (s *WebAuthnService) webauthnUserFor(ctx context.Context, user *models.User) (*webAuthnUser, error) {
	passkeys, err := s.passkeyRepo.GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(passkeys))
	for i := range passkeys {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(passkeys[i].CredentialJSON), &c); err != nil {
			s.logger.Warn(logging.Postgres, logging.Select, "webauthn: skipping malformed credential", map[logging.ExtraKey]interface{}{
				"passkeyId": passkeys[i].ID,
			})
			continue
		}
		creds = append(creds, c)
	}
	return &webAuthnUser{
		id:          user.ID[:],
		name:        user.Email,
		displayName: user.FullName(),
		credentials: creds,
	}, nil
}

func (s *WebAuthnService) saveSession(ctx context.Context, purpose webAuthnSessionPurpose, sessionData *webauthn.SessionData) error {
	stored := &storedWebAuthnSession{Purpose: purpose, SessionData: *sessionData}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, database.WebAuthnKey(sessionData.Challenge), data, s.ttl).Err()
}

func (s *WebAuthnService) loadAndDeleteSession(ctx context.Context, challenge string) (*storedWebAuthnSession, error) {
	key := database.WebAuthnKey(challenge)
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrWebAuthnChallenge
		}
		return nil, err
	}
	s.rdb.Del(ctx, key)
	var stored storedWebAuthnSession
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, ErrWebAuthnChallenge
	}
	return &stored, nil
}

func sanitizePasskeyName(name string, user *models.User) string {
	if name == "" {
		name = user.FullName()
	}
	if len([]rune(name)) > 100 {
		runes := []rune(name)
		name = string(runes[:100])
	}
	if name == "" {
		name = "Passkey"
	}
	return name
}

func toPasskeyInfo(pk *models.Passkey) PasskeyInfo {
	info := PasskeyInfo{
		ID:        pk.ID.String(),
		Name:      pk.Name,
		AAGUID:    pk.AAGUID,
		Backup:    pk.BackupEligible,
		CreatedAt: pk.CreatedAt.Format(time.RFC3339),
	}
	if pk.LastUsedAt != nil {
		lu := pk.LastUsedAt.Format(time.RFC3339)
		info.LastUsedAt = &lu
	}
	return info
}
