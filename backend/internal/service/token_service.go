package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
)

// TokenClaims represents the claims in a JWT token
type TokenClaims struct {
	UserID      string   `json:"userId"`
	TenantID    string   `json:"tenantId,omitempty"` // Current tenant context
	Email       string   `json:"email"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	SessionID   string   `json:"sessionId"`
	TokenType   string   `json:"tokenType"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// JWK represents a JSON Web Key for JWKS response
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKSResponse represents the JWKS endpoint response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// KeyProvider handles loading and caching cryptographic keys
type KeyProvider struct {
	mu            sync.RWMutex
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	alg           string
	kid           string
	cfg           *config.JWTConfig
}

// NewKeyProvider creates a key provider from config
func NewKeyProvider(cfg *config.JWTConfig) (*KeyProvider, error) {
	kp := &KeyProvider{
		alg: cfg.Algorithm,
		kid: cfg.KeyID,
		cfg: cfg,
	}

	if cfg.Algorithm == "RS256" {
		if err := kp.loadRSAKeys(); err != nil {
			return nil, fmt.Errorf("failed to load RSA keys: %w", err)
		}
	}

	return kp, nil
}

func (kp *KeyProvider) loadRSAKeys() error {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	// Try PEM env vars first, then file paths
	var privPEM, pubPEM string

	if kp.cfg.PrivateKeyPEM != "" {
		privPEM = kp.cfg.PrivateKeyPEM
	} else if kp.cfg.PrivateKeyPath != "" {
		data, err := os.ReadFile(kp.cfg.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file %s: %w", kp.cfg.PrivateKeyPath, err)
		}
		privPEM = string(data)
	}

	if kp.cfg.PublicKeyPEM != "" {
		pubPEM = kp.cfg.PublicKeyPEM
	} else if kp.cfg.PublicKeyPath != "" {
		data, err := os.ReadFile(kp.cfg.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key file %s: %w", kp.cfg.PublicKeyPath, err)
		}
		pubPEM = string(data)
	}

	if privPEM == "" {
		return fmt.Errorf("no private key provided for RS256 (set JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM)")
	}

	// Parse private key
	privBlock, _ := pem.Decode([]byte(privPEM))
	if privBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	var privKey *rsa.PrivateKey
	if privBlock.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
		privKey = key
	} else if privBlock.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
	} else {
		return fmt.Errorf("unsupported private key type: %s", privBlock.Type)
	}

	kp.privateKey = privKey

	// Parse public key (or derive from private key)
	if pubPEM != "" {
		pubBlock, _ := pem.Decode([]byte(pubPEM))
		if pubBlock == nil {
			return fmt.Errorf("failed to decode public key PEM")
		}

		if pubBlock.Type == "RSA PUBLIC KEY" {
			key, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse PKIX public key: %w", err)
			}
			var ok bool
			kp.publicKey, ok = key.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("public key is not RSA")
			}
		} else if pubBlock.Type == "PUBLIC KEY" {
			key, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse PKIX public key: %w", err)
			}
			var ok bool
			kp.publicKey, ok = key.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("public key is not RSA")
			}
		} else {
			return fmt.Errorf("unsupported public key type: %s", pubBlock.Type)
		}
	} else {
		// Derive public key from private key
		kp.publicKey = &privKey.PublicKey
	}

	if kp.privateKey == nil || kp.publicKey == nil {
		return fmt.Errorf("failed to load RSA key pair")
	}

	return nil
}

// GetSigningMethod returns the JWT signing method
func (kp *KeyProvider) GetSigningMethod() jwt.SigningMethod {
	if kp.alg == "RS256" {
		return jwt.SigningMethodRS256
	}
	return jwt.SigningMethodHS256
}

// GetKeyID returns the key ID for the JWT header
func (kp *KeyProvider) GetKeyID() string {
	return kp.kid
}

// GetAlgorithm returns the signing algorithm name
func (kp *KeyProvider) GetAlgorithm() string {
	return kp.alg
}

// Sign signs the token with the appropriate key
func (kp *KeyProvider) Sign(token *jwt.Token, secret string) (string, error) {
	if kp.alg == "RS256" {
		kp.mu.RLock()
		defer kp.mu.RUnlock()
		if kp.privateKey == nil {
			return "", fmt.Errorf("private key not loaded")
		}
		return token.SignedString(kp.privateKey)
	}
	return token.SignedString([]byte(secret))
}

// GetVerifyKey returns the key used for token verification
func (kp *KeyProvider) GetVerifyKey(token *jwt.Token) (interface{}, error) {
	if kp.alg == "RS256" {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kp.mu.RLock()
		defer kp.mu.RUnlock()
		if kp.publicKey == nil {
			return nil, fmt.Errorf("public key not loaded")
		}
		return kp.publicKey, nil
	}
	// HS256
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return nil, nil // Secret provided at call site
}

// GenerateJWKS generates a JWKS response from the public key
func (kp *KeyProvider) GenerateJWKS() (*JWKSResponse, error) {
	if kp.alg != "RS256" {
		return nil, fmt.Errorf("JWKS is only available when using RS256")
	}

	kp.mu.RLock()
	defer kp.mu.RUnlock()

	if kp.publicKey == nil {
		return nil, fmt.Errorf("public key not loaded")
	}

	n := base64.RawURLEncoding.EncodeToString(kp.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.publicKey.E)).Bytes())

	return &JWKSResponse{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: kp.kid,
				Alg: "RS256",
				N:   n,
				E:   e,
			},
		},
	}, nil
}

// TokenService handles JWT operations
type TokenService struct {
	cfg     *config.JWTConfig
	keyProv *KeyProvider
}

func NewTokenService(cfg *config.JWTConfig, keyProv *KeyProvider) *TokenService {
	return &TokenService{cfg: cfg, keyProv: keyProv}
}

// GenerateAccessToken creates a new access token
func (s *TokenService) GenerateAccessToken(user *models.User, tenantID *uuid.UUID, roles []string, permissions []string, sessionID uuid.UUID) (string, error) {
	now := time.Now()

	tenantIDStr := ""
	if tenantID != nil {
		tenantIDStr = tenantID.String()
	} else if user.TenantID != nil {
		tenantIDStr = user.TenantID.String()
	}

	// Build audience list
	audiences := []string{s.cfg.Audience}
	if s.cfg.Audience != "" {
		audiences = []string{s.cfg.Audience}
	}

	claims := TokenClaims{
		UserID:      user.ID.String(),
		TenantID:    tenantIDStr,
		Email:       CleanEmail(user.Email),
		Username:    user.Username,
		Roles:       roles,
		Permissions: permissions,
		SessionID:   sessionID.String(),
		TokenType:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   user.ID.String(),
			Audience:  audiences,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(s.keyProv.GetSigningMethod(), claims)
	token.Header["kid"] = s.keyProv.GetKeyID()
	return s.keyProv.Sign(token, s.cfg.Secret)
}

// GenerateRefreshToken creates a new refresh token
func (s *TokenService) GenerateRefreshToken(userID, sessionID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.cfg.RefreshExpiry)

	audiences := []string{s.cfg.Audience}
	if s.cfg.Audience != "" {
		audiences = []string{s.cfg.Audience}
	}

	claims := TokenClaims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID.String(),
			Audience:  audiences,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(s.keyProv.GetSigningMethod(), claims)
	token.Header["kid"] = s.keyProv.GetKeyID()
	tokenString, err := s.keyProv.Sign(token, s.cfg.Secret)
	return tokenString, expiresAt, err
}

// GenerateTwoFactorToken creates a short-lived token for the 2FA login step.
func (s *TokenService) GenerateTwoFactorToken(userID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(5 * time.Minute)

	claims := TokenClaims{
		UserID:    userID.String(),
		TokenType: "2fa",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(s.keyProv.GetSigningMethod(), claims)
	token.Header["kid"] = s.keyProv.GetKeyID()
	tokenString, err := s.keyProv.Sign(token, s.cfg.Secret)
	return tokenString, expiresAt, err
}

// ValidateTwoFactorToken validates a 2FA challenge token.
func (s *TokenService) ValidateTwoFactorToken(tokenString string) (*TokenClaims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "2fa" {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

// ValidateToken validates a token and returns the claims
func (s *TokenService) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate algorithm
		alg := token.Header["alg"]
		if alg == nil {
			return nil, fmt.Errorf("missing algorithm in token header")
		}

		algStr, ok := alg.(string)
		if !ok {
			return nil, fmt.Errorf("invalid algorithm in token header")
		}

		// Reject alg=none
		if algStr == "none" {
			return nil, fmt.Errorf("alg=none is not allowed")
		}

		// For RS256, use the public key from key provider
		if algStr == "RS256" {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method for RS256: %v", algStr)
			}
			return s.keyProv.GetVerifyKey(token)
		}

		// For HS256
		if algStr == "HS256" {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method for HS256: %v", algStr)
			}
			return []byte(s.cfg.Secret), nil
		}

		return nil, fmt.Errorf("unsupported algorithm: %s", algStr)
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	// Validate issuer
	if claims.Issuer != s.cfg.Issuer {
		return nil, ErrTokenInvalid
	}

	// Validate audience (if configured)
	if s.cfg.Audience != "" {
		if len(claims.Audience) == 0 {
			return nil, ErrTokenInvalid
		}
		audienceValid := false
		for _, aud := range claims.Audience {
			if aud == s.cfg.Audience {
				audienceValid = true
				break
			}
		}
		if !audienceValid {
			return nil, ErrTokenInvalid
		}
	}

	return claims, nil
}

// ExtractTokenFromHeader extracts token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrTokenRequired
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrTokenInvalid
	}

	return parts[1], nil
}

// GenerateOTPCode generates a random OTP code
func GenerateOTPCode(length int) (string, error) {
	if length <= 0 {
		length = 6
	}

	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}
