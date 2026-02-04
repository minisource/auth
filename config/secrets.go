package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SecretProvider interface for loading secrets
type SecretProvider interface {
	GetSecret(key string) (string, error)
}

// EnvSecretProvider loads secrets from environment variables
type EnvSecretProvider struct{}

func (p *EnvSecretProvider) GetSecret(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("secret %s not found in environment", key)
	}
	return value, nil
}

// FileSecretProvider loads secrets from a JSON file
type FileSecretProvider struct {
	filePath string
	secrets  map[string]string
}

func NewFileSecretProvider(filePath string) (*FileSecretProvider, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets file: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse secrets file: %w", err)
	}

	return &FileSecretProvider{
		filePath: filePath,
		secrets:  secrets,
	}, nil
}

func (p *FileSecretProvider) GetSecret(key string) (string, error) {
	value, exists := p.secrets[key]
	if !exists {
		return "", fmt.Errorf("secret %s not found in file", key)
	}
	return value, nil
}

// DockerSecretProvider loads secrets from Docker secrets (/run/secrets/)
type DockerSecretProvider struct {
	secretsPath string
}

func NewDockerSecretProvider() *DockerSecretProvider {
	return &DockerSecretProvider{
		secretsPath: "/run/secrets",
	}
}

func (p *DockerSecretProvider) GetSecret(key string) (string, error) {
	// Convert KEY_NAME to key_name for file lookup
	fileName := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	filePath := fmt.Sprintf("%s/%s", p.secretsPath, fileName)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read Docker secret %s: %w", key, err)
	}

	return strings.TrimSpace(string(data)), nil
}

// ChainSecretProvider tries multiple providers in order
type ChainSecretProvider struct {
	providers []SecretProvider
}

func NewChainSecretProvider(providers ...SecretProvider) *ChainSecretProvider {
	return &ChainSecretProvider{
		providers: providers,
	}
}

func (p *ChainSecretProvider) GetSecret(key string) (string, error) {
	var lastErr error
	for _, provider := range p.providers {
		value, err := provider.GetSecret(key)
		if err == nil {
			return value, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("secret %s not found in any provider: %w", key, lastErr)
}

// GetSecretOrDefault gets a secret or returns a default value
func GetSecretOrDefault(provider SecretProvider, key, defaultValue string) string {
	value, err := provider.GetSecret(key)
	if err != nil {
		return defaultValue
	}
	return value
}

// LoadSecretsFromProvider updates config with secrets from provider
func LoadSecretsFromProvider(cfg *Config, provider SecretProvider) error {
	// PostgreSQL password
	if password, err := provider.GetSecret("DB_PASSWORD"); err == nil {
		cfg.Postgres.Password = password
	}

	// JWT secrets
	if secret, err := provider.GetSecret("JWT_SECRET"); err == nil {
		cfg.JWT.Secret = secret
	}

	// Redis password
	if password, err := provider.GetSecret("REDIS_PASSWORD"); err == nil {
		cfg.Redis.Password = password
	}

	// Google OAuth secrets
	if secret, err := provider.GetSecret("GOOGLE_CLIENT_SECRET"); err == nil {
		cfg.Google.ClientSecret = secret
	}

	return nil
}
