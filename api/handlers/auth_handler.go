package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/services"
	"github.com/minisource/common_go/http/helper"
	commonServices "github.com/minisource/common_go/http/services"
)

type AuthHandler struct {
	authService  *services.AuthService
	tokenService *commonServices.TokenService
}

func NewAuthHandler(cfg *config.Config) *AuthHandler {
	authService := services.NewAuthService(cfg)
	tokenService := commonServices.NewTokenService(&cfg.UserJWT)

	return &AuthHandler{
		authService: authService,
		tokenService: tokenService,
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

	// Return a success response
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(nil, true, helper.Success),
	)
}

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
// @Router /v1/auth/verify-otp [post]
func (h *AuthHandler) VerifyOtp(c *fiber.Ctx) error {
	// Parse the request body
	req := new(dto.VerifyOtpRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
		)
	}

	token, err := h.authService.LoginByPhoneNumber(req)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the generated token
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(token, true, helper.Success),
	)
}

// ValidateToken godoc
// @Summary ValidateToken
// @Description ValidateToken
// @Tags ValidateToken
// @Accept json
// @Produce json
// @Success 201 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Failure 409 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/auth/ValidateToken [post]
func (h *AuthHandler) ValidateToken(c *fiber.Ctx) error {
	// Parse the request body
	req := new(dto.ValidateAccessTokenRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
		)
	}

	claims, err := h.tokenService.GetClaims(req.AccessToken)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the generated token
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(dto.ValidateAuthTokenRes{Claims: claims}, true, helper.Success),
	)
}
