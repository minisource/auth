package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/i18n"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// WebAuthnHandler exposes passkey registration (authenticated) and passkey
// login (public) endpoints.
type WebAuthnHandler struct {
	svc    *service.WebAuthnService
	logger logging.Logger
}

func NewWebAuthnHandler(svc *service.WebAuthnService, logger logging.Logger) *WebAuthnHandler {
	return &WebAuthnHandler{svc: svc, logger: logger}
}

func (h *WebAuthnHandler) assertEnabled(c *fiber.Ctx) error {
	if !h.svc.IsEnabled() {
		return response.ServiceUnavailable(c, i18n.T(c.Context(), "errors.webauthn_failed"))
	}
	return nil
}

// BeginRegistration godoc
// @Summary Begin passkey registration
// @Description Start a WebAuthn registration ceremony; returns credential creation options for the browser
// @Tags Passkeys
// @Produce json
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/passkeys/register/begin [post]
func (h *WebAuthnHandler) BeginRegistration(c *fiber.Ctx) error {
	if err := h.assertEnabled(c); err != nil {
		return err
	}
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	creation, err := h.svc.BeginRegistration(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(creation)
}

// FinishRegistration godoc
// @Summary Finish passkey registration
// @Description Validate the authenticator response and store the new passkey
// @Tags Passkeys
// @Accept json
// @Produce json
// @Param request body dto.PasskeyRegistrationFinishRequest true "Passkey name + credential response"
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/passkeys/register/finish [post]
func (h *WebAuthnHandler) FinishRegistration(c *fiber.Ctx) error {
	if err := h.assertEnabled(c); err != nil {
		return err
	}
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req dto.PasskeyRegistrationFinishRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}
	passkey, err := h.svc.FinishRegistration(c.Context(), userID, req.Name, req.Credential)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	// Raw JSON like the other /users/me/* endpoints (no envelope).
	return c.JSON(passkey)
}

// ListPasskeys godoc
// @Summary List passkeys
// @Description List the current user's registered passkeys
// @Tags Passkeys
// @Produce json
// @Security BearerAuth
// @Success 200 {array} service.PasskeyInfo
// @Router /users/me/passkeys [get]
func (h *WebAuthnHandler) ListPasskeys(c *fiber.Ctx) error {
	if err := h.assertEnabled(c); err != nil {
		return err
	}
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	passkeys, err := h.svc.ListPasskeys(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	if passkeys == nil {
		passkeys = []service.PasskeyInfo{}
	}
	return c.JSON(passkeys)
}

// DeletePasskey godoc
// @Summary Delete a passkey
// @Description Remove a registered passkey from the current user's account
// @Tags Passkeys
// @Param id path string true "Passkey ID"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Router /users/me/passkeys/{id} [delete]
func (h *WebAuthnHandler) DeletePasskey(c *fiber.Ctx) error {
	if err := h.assertEnabled(c); err != nil {
		return err
	}
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid passkey ID")
	}
	if err := h.svc.DeletePasskey(c.Context(), userID, id); err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(dto.MessageResponse{Message: "Passkey deleted"})
}

// BeginLogin godoc
// @Summary Begin passkey login
// @Description Start a WebAuthn login ceremony for an email; returns assertion options for the browser
// @Tags Passkeys
// @Accept json
// @Produce json
// @Param request body dto.PasskeyLoginBeginRequest true "Email"
// @Success 200 {object} object
// @Router /auth/webauthn/begin [post]
func (h *WebAuthnHandler) BeginLogin(c *fiber.Ctx) error {
	if err := h.assertEnabled(c); err != nil {
		return err
	}
	var req dto.PasskeyLoginBeginRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}
	assertion, err := h.svc.BeginLogin(c.Context(), req.Email)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(assertion)
}

// FinishLogin godoc
// @Summary Finish passkey login
// @Description Validate the assertion and sign the user in
// @Tags Passkeys
// @Accept json
// @Produce json
// @Param request body dto.PasskeyLoginFinishRequest true "Assertion response"
// @Success 200 {object} service.AuthResponse
// @Router /auth/webauthn/finish [post]
func (h *WebAuthnHandler) FinishLogin(c *fiber.Ctx) error {
	if err := h.assertEnabled(c); err != nil {
		return err
	}
	var req dto.PasskeyLoginFinishRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}
	resp, err := h.svc.FinishLogin(c.Context(), req.Credential, c.IP(), c.Get("User-Agent"))
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return response.OK(c, resp)
}
