package services

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/minisource/auth/config"
	"github.com/minisource/auth/data/models"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
	// "github.com/mitchellh/mapstructure"
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

// User state constants as pointers to strings
var (
	UserStateActive   = stringPtr("active")
	UserStateInactive = stringPtr("inactive")
	UserStateDisabled = stringPtr("disabled")
	UserStateRecovery = stringPtr("recovery")
)

func stringPtr(s string) *string {
	return &s
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
// / how to use
//
//	filter := map[string]interface{}{
//	    "email": "user@example.com",
//	}
//
// or
//
//	filter := map[string]interface{}{
//		   "phone_number": "1234567890",
//	}
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

// https://www.ory.sh/docs/reference/api#tag/identity/operation/batchPatchIdentities
func (s *UserService) CreateInactiveUserWithMobile(phoneNumber string) (*kratos.Identity, error) {
	// TODO:
	// traitsStruct := models.UserCustomTraits{
	// 	PhoneNumber: phoneNumber,
	// }
	// traits := make(map[string]interface{})
	// mapstructure.Decode(traitsStruct, &traits)
	traits := map[string]interface{}{
		"phone_number": phoneNumber,
	}

	verifiableAddresses := []kratos.VerifiableIdentityAddress{
		{
			Value:    phoneNumber,
			Via:      "mobile",
			Status:   "pending", // Unverified status
			Verified: false,     // Not verified yet
		},
	}

	newUser, httpResponse, err := s.Kratos.IdentityAPI.CreateIdentity(context.Background()).CreateIdentityBody(kratos.CreateIdentityBody{
		SchemaId:            "default",
		Traits:              traits,
		State:               UserStateInactive,
		VerifiableAddresses: verifiableAddresses,
	}).Execute()
	if err != nil {
		s.logger.Fatalf("Failed to create user: %v, http response: %v", err, httpResponse)
		return nil, err
	}

	return newUser, nil
}

func (s *UserService) ActiveUser(phoneNumber string) error {
	existingUser, _, err := s.CheckUserExists(map[string]interface{}{"phone_number": phoneNumber})
	if err != nil {
		s.logger.Fatalf("failed to fetch identity: %w", err)
		return err
	}

	// تغییر وضعیت شماره موبایل به تایید شده
	for i, addr := range existingUser.VerifiableAddresses {
		if addr.Via == "mobile" && addr.Value == phoneNumber {
			existingUser.VerifiableAddresses[i].Verified = true
			existingUser.VerifiableAddresses[i].Status = "completed"
			existingUser.VerifiableAddresses[i].VerifiedAt = kratos.PtrTime(time.Now())
		}
	}

	// Convert the *kratos.Identity to an UpdateIdentityBody
	updateBody := kratos.UpdateIdentityBody{
		SchemaId: existingUser.SchemaId,
		State:    *UserStateActive,
		Traits: existingUser.Traits.(map[string]interface{}),
	}

	_, httpResponse, err := s.Kratos.IdentityAPI.UpdateIdentity(context.Background(), existingUser.Id).UpdateIdentityBody(updateBody).Execute()
	if err != nil {
		s.logger.Fatalf("failed to update identity: %v, http response: %v", err, httpResponse)
		return err
	}

	return nil
}

func (s *UserService) UpdateUser(traits models.UserCustomTraits) error {
	// Fetch the existing user
	existingUser, _, err := s.CheckUserExists(map[string]interface{}{"phone_number": traits.PhoneNumber})
	if err != nil {
		s.logger.Fatalf("failed to fetch identity: %w", err)
		return err
	}

	/// traits
	traitsMap := make(map[string]interface{})
	// Marshal the inputTraits struct to JSON, then unmarshal it into a map
	traitsJSON, err := json.Marshal(traits)
	if err != nil {
		s.logger.Fatalf("failed to marshal inputTraits: %w", err)
		return err
	}
	// Unmarshal JSON to a map
	err = json.Unmarshal(traitsJSON, &traitsMap)
	if err != nil {
		s.logger.Fatalf("failed to unmarshal inputTraits to map: %w", err)
		return err
	}
	// Merge the new traits map into the existing user traits (if it exists)
	if existingUser.Traits == nil {
		existingUser.Traits = make(map[string]interface{})
	}
	// Assert existingUser.Traits to a map
	existingTraits, ok := existingUser.Traits.(map[string]interface{})
	if !ok {
		s.logger.Fatalf("failed to assert existingUser.Traits to map[string]interface{}")
		return err
	}
	// Using a for loop to merge traits from traitsMap to existingUser.Traits
	for key, value := range traitsMap {
		// Merge each field from inputTraits into existingUser.Traits
		existingTraits[key] = value
	}
	existingUser.Traits = existingTraits

	// Convert the *kratos.Identity to an UpdateIdentityBody
	updateBody := kratos.UpdateIdentityBody{
		SchemaId: existingUser.SchemaId,
		Traits:   existingUser.Traits.(map[string]interface{}),
	}

	_, _, err = s.Kratos.IdentityAPI.UpdateIdentity(context.Background(), existingUser.Id).UpdateIdentityBody(updateBody).Execute()
	if err != nil {
		s.logger.Fatalf("failed to update identity: %w", err)
		return err
	}

	return nil
}
