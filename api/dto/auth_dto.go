package dto

type GetOtpRequest struct {
	MobileNumber string `json:"mobileNumber" binding:"required,mobile"`
}
type GetOtpResponse struct {
	IsUserExist bool `json:"isUserExist"`
}

type VerifyOtpRequest struct {
	MobileNumber string `json:"mobileNumber" binding:"required,mobile"`
	Otp          string `json:"otp" binding:"required,min=6,max=6"`
}