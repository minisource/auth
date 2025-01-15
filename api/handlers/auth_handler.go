package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/services"
	"github.com/minisource/common_go/http/helper"
)

type AuthHandler struct {
	authService *services.AuthService
	userService *services.UserService
}

func NewAuthHandler(cfg *config.Config) *AuthHandler {
	authService := services.NewAuthService(cfg)
	userService := services.NewUserService(cfg)

	return &AuthHandler{
		authService: authService,
		userService: userService,
	}
}

// SendOtp godoc
// @Summary Send OTP to user
// @Description Send OTP to user
// @Tags Users
// @Accept json
// @Produce json
// @Param Request body dto.GetOtpRequest true "GetOtpRequest"
// @Success 201 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Failure 409 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/users/send-otp [post]
func (h *AuthHandler) SendOtp(c *fiber.Ctx) error {
	// Parse the request body
	req := new(dto.GetOtpRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
		)
	}

	// Call the service to send the OTP
	err := h.authService.SendOtp(req)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	_, isExist, err := h.userService.CheckUserExists(map[string]interface{}{"phone_number": req.MobileNumber})
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}
	
	// Return a success response
	return c.Status(fiber.StatusCreated).JSON(
		helper.GenerateBaseResponse(dto.GetOtpResponse{IsUserExist: isExist}, true, helper.Success),
	)
}

// TODO: implement verify otp
// VerifyOtp godoc
// @Summary Register or login by mobile number
// @Description Register or login by mobile number
// @Tags Users
// @Accept json
// @Produce json
// @Param Request body dto.RegisterLoginByMobileRequest true "RegisterLoginByMobileRequest"
// @Success 201 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Failure 409 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/users/login-by-mobile [post]
// func (h *AuthHandler) VerifyOtp(c *fiber.Ctx) error {
// 	// Parse the request body
// 	req := new(dto.VerifyOtpRequest)
// 	if err := c.BodyParser(req); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(
// 			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
// 		)
// 	}

// 	token, err := h.service.VerifyOtp(req)
// 	if err != nil {
// 		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
// 			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
// 		)
// 	}

// 	// Return the generated token
// 	return c.Status(fiber.StatusCreated).JSON(
// 		helper.GenerateBaseResponse(token, true, helper.Success),
// 	)
// }
