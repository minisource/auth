package dto

type GetOtpRequest struct {
	PhoneNumber string `json:"phoneNumber" binding:"required,mobile"`
}

type VerifyOtpRequest struct {
	PhoneNumber string `json:"phoneNumber" binding:"required,mobile"`
	Otp         string `json:"otp" binding:"required,min=6,max=6"`
}

type ValidateAccessTokenRequest struct {
	AccessToken string `json:"accessToken"`
}

type ValidateAuthTokenRes struct {
	Claims map[string]interface{} `json:"claims"`
}
