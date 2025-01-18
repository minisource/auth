package services

import (
	"context"

	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/common"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
	"github.com/minisource/common_go/service_errors"
	"github.com/ory/hydra-client-go"
	hydra "github.com/ory/hydra-client-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type OAuthService struct {
	logger logging.Logger
	cfg    *config.Config
	hydra  *hydra.APIClient
}

func NewOAuthService(cfg *config.Config) *OAuthService {
	logger := logging.NewLogger(&cfg.Logger)
	return &OAuthService{
		logger: logger,
		cfg:    cfg,
		hydra:  ory.GetHydra(),
	}
}

// https://www.ory.sh/docs/hydra/cli/hydra-create-client
func (s *OAuthService) CreateClient(req *dto.CreateOAuthClientRequest) (*client.OAuth2Client, error) {
	newClient := hydra.OAuth2Client{
		ClientId:      req.ClientId,
		ClientSecret:  req.ClientSecret,
		GrantTypes:    []string{"client_credentials"},
		ResponseTypes: []string{"token"},
		Scope:         req.Scope,
		Audience:      req.Audience,
	}

	createdClient, _, err := s.hydra.AdminApi.CreateOAuth2Client(context.Background()).OAuth2Client(newClient).Execute()
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, err.Error(), map[logging.ExtraKey]interface{}{logging.AppName: "hydra"})
		return nil, err
	}

	return createdClient, nil
}

// https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/listOAuth2Clients
func (s *OAuthService) GetAllClients() ([]client.OAuth2Client, error) {
	clients, _, err := s.hydra.AdminApi.ListOAuth2Clients(context.Background()).Execute()
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, err.Error(), map[logging.ExtraKey]interface{}{logging.AppName: "hydra"})
		return nil, err
	}
	return clients, nil
}

// https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/deleteOAuth2Client
func (s *OAuthService) DeleteClient(id string) error {
	_, err := s.hydra.AdminApi.DeleteOAuth2Client(context.Background(), id).Execute()
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, err.Error(), map[logging.ExtraKey]interface{}{logging.AppName: "hydra"})
		return err
	}
	return nil
}

// https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/getOAuth2Client
func (s *OAuthService) GetClient(id string) (*client.OAuth2Client, error) {
	client, _, err := s.hydra.AdminApi.GetOAuth2Client(context.Background(), id).Execute()
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, err.Error(), map[logging.ExtraKey]interface{}{logging.AppName: "hydra"})
		return nil, err
	}

	return client, nil
}

// https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/oauth2TokenExchange
func (s *OAuthService) GenerateToken(req *dto.GenerateTokenRequest) (*oauth2.Token, error) {
	config := clientcredentials.Config{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		TokenURL:     s.cfg.Hydra.PublicURL + "/oauth2/token",
		Scopes:       req.Scopes,
	}

	token, err := config.Token(context.Background())
	if err != nil {
		s.logger.Error(logging.General, logging.ExternalService, err.Error(), map[logging.ExtraKey]interface{}{logging.AppName: "hydra"})
		return nil, err
	}

	return token, nil
}

// https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/introspectOAuth2Token
func (s *OAuthService) ValidateToken(req dto.ValidateTokenRequest) (*hydra.OAuth2TokenIntrospection, error) {
	introspection, _, err := s.hydra.AdminApi.IntrospectOAuth2Token(context.Background()).Token(req.Token).Execute()
	if err != nil {
		return nil, &service_errors.ServiceError{EndUserMessage: service_errors.TokenInvalid, Err: err}
	}
	token, err := s.GetClient(*introspection.ClientId)
	if err != nil {
		return nil, &service_errors.ServiceError{EndUserMessage: service_errors.TokenInvalid, Err: err}
	}

	// بررسی اینکه توکن فعال است یا خیر
	if !introspection.GetActive() {
		return nil, &service_errors.ServiceError{EndUserMessage: service_errors.UnExpectedError, Err: err}
	}

	// بررسی Claim‌ها
	if req.Scop != nil {
		if introspection.GetScope() != *req.Scop {
			return nil, &service_errors.ServiceError{EndUserMessage: "Invalid scope for this service", Err: err}
		}
	}

	if req.Audience != nil && len(*req.Audience) > 0 {
		introspectionAud, anyAudExist := token.GetAudienceOk()
		if !anyAudExist || !common.ContainsAll(introspectionAud, *req.Audience) {
			return nil, &service_errors.ServiceError{EndUserMessage: "Invalid audience for this service", Err: err}
		}
	}

	return introspection, nil
}
