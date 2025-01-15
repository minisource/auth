package services

import (
	"context"
	"sync"

	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
	kratos "github.com/ory/kratos-client-go"
)

type UserService struct {
	logger logging.Logger
	cfg    *config.Config
	Kratos *kratos.APIClient
}

func NewUserService(cfg *config.Config) *UserService {
	logger := logging.NewLogger(&cfg.Logger)

	return &UserService{
		logger: logger,
		cfg:    cfg,
		Kratos: ory.GetKratos(),
	}
}


// https://www.ory.sh/docs/reference/api#tag/identity
func (s *UserService) GetListUsers() ([]kratos.Identity, error) {
	identities, httpResponse, err := s.Kratos.IdentityAPI.ListIdentities(context.Background()).Execute()
	if err != nil {
		s.logger.Fatalf("Failed to list identities: %v", err, httpResponse)
		return nil, err
	}

	return identities, nil
}

// https://www.ory.sh/docs/reference/api#tag/identity/operation/getIdentity
/// how to use 
// filter := map[string]interface{}{
//     "email": "user@example.com",
// }
//or
// filter := map[string]interface{}{
// 	   "phone_number": "1234567890",
// }
func (s *UserService) CheckUserExists(filter map[string]interface{}) (*kratos.Identity, bool, error) {
	identities, err := s.GetListUsers()
	if err != nil {
		return nil, false, err
	}

	var wg sync.WaitGroup
	var result *kratos.Identity
	var found bool
	var mu sync.Mutex

	for _, identity := range identities {
		wg.Add(1)
		go func(id kratos.Identity) {
			defer wg.Done()
			match := true
			for key, value := range filter {
				traits, ok := id.Traits.(map[string]interface{})
				if !ok {
					return
				}
				if traits[key] != value {
					match = false
					break
				}
			}
			if match {
				mu.Lock()
				if !found {
					result = &id
					found = true
				}
				mu.Unlock()
			}
		}(identity)
	}

	wg.Wait()
	return result, found, nil
}
