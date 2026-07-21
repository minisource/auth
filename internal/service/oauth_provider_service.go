package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
	service_errors "github.com/minisource/go-common/service_errors"
)

type OAuthProviderService interface {
	Create(ctx context.Context, provider *models.OAuthProvider) (*models.OAuthProvider, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthProvider, error)
	List(ctx context.Context, tenantID *uuid.UUID, page, pageSize int) ([]models.OAuthProvider, int64, error)
	Update(ctx context.Context, id uuid.UUID, updates map[string]interface{}) (*models.OAuthProvider, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ToggleEnabled(ctx context.Context, id uuid.UUID) (*models.OAuthProvider, error)
	GetByType(ctx context.Context, providerType string, tenantID *uuid.UUID) (*models.OAuthProvider, error)
	IncrementStats(ctx context.Context, id uuid.UUID, successful bool) error
}

type oauthProviderService struct {
	repo   repository.OAuthProviderRepository
	logger logging.Logger
}

func NewOAuthProviderService(repo repository.OAuthProviderRepository, logger logging.Logger) OAuthProviderService {
	return &oauthProviderService{repo: repo, logger: logger}
}

func (s *oauthProviderService) Create(ctx context.Context, provider *models.OAuthProvider) (*models.OAuthProvider, error) {
	if err := s.repo.Create(ctx, provider); err != nil {
		return nil, err
	}
	return provider, nil
}

func (s *oauthProviderService) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthProvider, error) {
	provider, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "OAuth provider not found",
		}
	}
	return provider, nil
}

func (s *oauthProviderService) List(ctx context.Context, tenantID *uuid.UUID, page, pageSize int) ([]models.OAuthProvider, int64, error) {
	offset := (page - 1) * pageSize
	return s.repo.List(ctx, tenantID, offset, pageSize)
}

func (s *oauthProviderService) Update(ctx context.Context, id uuid.UUID, updates map[string]interface{}) (*models.OAuthProvider, error) {
	provider, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "OAuth provider not found",
		}
	}

	if name, ok := updates["name"].(string); ok {
		provider.Name = name
	}
	if clientID, ok := updates["clientId"].(string); ok {
		provider.ClientID = clientID
	}
	if clientSecret, ok := updates["clientSecret"].(string); ok {
		provider.ClientSecret = clientSecret
	}
	if redirectURL, ok := updates["redirectUrl"].(string); ok {
		provider.RedirectURL = redirectURL
	}
	if scopes, ok := updates["scopes"].(string); ok {
		provider.Scopes = scopes
	}
	if authURL, ok := updates["authUrl"].(string); ok {
		provider.AuthURL = authURL
	}
	if tokenURL, ok := updates["tokenUrl"].(string); ok {
		provider.TokenURL = tokenURL
	}
	if userInfoURL, ok := updates["userInfoUrl"].(string); ok {
		provider.UserInfoURL = userInfoURL
	}
	if config, ok := updates["config"].(models.OAuthProviderConfig); ok {
		provider.Config = config
	}

	provider.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (s *oauthProviderService) Delete(ctx context.Context, id uuid.UUID) error {
	provider, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if provider == nil {
		return &service_errors.ServiceError{
			EndUserMessage: "OAuth provider not found",
		}
	}
	return s.repo.Delete(ctx, id)
}

func (s *oauthProviderService) ToggleEnabled(ctx context.Context, id uuid.UUID) (*models.OAuthProvider, error) {
	provider, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, &service_errors.ServiceError{
			EndUserMessage: "OAuth provider not found",
		}
	}

	provider.IsEnabled = !provider.IsEnabled
	provider.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (s *oauthProviderService) GetByType(ctx context.Context, providerType string, tenantID *uuid.UUID) (*models.OAuthProvider, error) {
	return s.repo.GetByType(ctx, providerType, tenantID)
}

func (s *oauthProviderService) IncrementStats(ctx context.Context, id uuid.UUID, successful bool) error {
	return s.repo.IncrementStats(ctx, id, successful)
}
