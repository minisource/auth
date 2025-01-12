package dto

type CreateOAuthClientRequest struct {
	// ID  is the id for this client.
	ClientId *string `json:"client_id,omitempty"`
	// Secret is the client's secret. The secret will be included in the create request as cleartext, and then never again. The secret is stored using BCrypt so it is impossible to recover it. Tell your users that they need to write the secret down as it will not be made available again.
	ClientSecret *string `json:"client_secret,omitempty"`
	// Scope is a string containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens.
	Scope *string `json:"scope,omitempty"`
}

type GenerateTokenRequest struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

type ValidateTokenRequest struct {
	Token     string `json:"token"`
}

