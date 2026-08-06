package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// AdminSessionHandler handles admin session management endpoints
type AdminSessionHandler struct {
	sessionRepo       repository.SessionRepository
	refreshTokenRepo  repository.RefreshTokenRepository
	logger            logging.Logger
}

func NewAdminSessionHandler(
	sessionRepo repository.SessionRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	logger logging.Logger,
) *AdminSessionHandler {
	return &AdminSessionHandler{
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		logger:           logger,
	}
}

// ListAllSessions godoc
// @Summary List all sessions
// @Description Get sessions across all users with search, filter, and sort
// @Tags Admin/Sessions
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Results per page" default(20)
// @Param search query string false "Search email, name, IP, user agent, or user ID"
// @Param userId query string false "Filter by user ID"
// @Param isActive query bool false "Filter by active status"
// @Param orderBy query string false "Sort field (createdAt, lastActiveAt, expiresAt, ipAddress)" default(createdAt)
// @Param sort query string false "Sort direction (asc, desc)" default(desc)
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/sessions [get]
func (h *AdminSessionHandler) ListAllSessions(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 20)
	search := c.Query("search")
	orderBy := c.Query("orderBy", "createdAt")
	sort := c.Query("sort", "desc")

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	filter := repository.SessionListFilter{
		Search:  search,
		OrderBy: orderBy,
		Sort:    sort,
		Limit:   limit,
		Offset:  offset,
	}

	if tenantHeader := c.Get("X-Tenant-ID"); tenantHeader != "" && tenantHeader != "all" {
		if parsed, err := uuid.Parse(tenantHeader); err == nil {
			filter.TenantID = &parsed
		}
	}

	if userIDStr := c.Query("userId"); userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
		}
		filter.UserID = &userID
	}

	if isActiveStr := c.Query("isActive"); isActiveStr != "" {
		isActive := isActiveStr == "true" || isActiveStr == "1"
		filter.IsActive = &isActive
	}

	sessions, total, err := h.sessionRepo.ListAll(c.Context(), filter)
	if err != nil {
		return response.InternalError(c, "Failed to fetch sessions")
	}

	if sessions == nil {
		sessions = []repository.SessionWithUser{}
	}

	return response.New().Data(fiber.Map{
		"data": sessions,
		"meta": fiber.Map{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (int(total) + limit - 1) / limit,
		},
	}).Send(c)
}

// RevokeSession godoc
// @Summary Revoke a session
// @Description Force logout a specific session
// @Tags Admin/Sessions
// @Param id path string true "Session ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/sessions/{id} [delete]
func (h *AdminSessionHandler) RevokeSession(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid session ID")
	}

	session, err := h.sessionRepo.GetByID(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	if session == nil {
		return response.NotFound(c, "Session not found")
	}

	if err := h.sessionRepo.Revoke(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	if err := h.sessionRepo.InvalidateCachedSession(c.Context(), id.String()); err != nil {
		h.logger.Error(logging.Redis, logging.Delete, "Failed to invalidate cached session", map[logging.ExtraKey]interface{}{
			"sessionID": id.String(),
			"error":     err.Error(),
		})
	}

	if session.RefreshToken != "" {
		if err := h.refreshTokenRepo.Revoke(c.Context(), session.RefreshToken); err != nil {
			h.logger.Error(logging.Redis, logging.Delete, "Failed to revoke refresh token", map[logging.ExtraKey]interface{}{
				"sessionID": id.String(),
				"error":     err.Error(),
			})
		}
	}

	return response.New().Data(fiber.Map{"message": "Session revoked successfully"}).Send(c)
}

// RevokeUserAllSessions godoc
// @Summary Revoke all sessions for a user
// @Description Force logout all sessions for a specific user
// @Tags Admin/Sessions
// @Param userId path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/users/{userId}/sessions [delete]
func (h *AdminSessionHandler) RevokeUserAllSessions(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	activeSessions, err := h.sessionRepo.GetByUserID(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	if err := h.sessionRepo.RevokeAllByUserID(c.Context(), userID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	for _, session := range activeSessions {
		if err := h.sessionRepo.InvalidateCachedSession(c.Context(), session.ID.String()); err != nil {
			h.logger.Error(logging.Redis, logging.Delete, "Failed to invalidate cached session", map[logging.ExtraKey]interface{}{
				"sessionID": session.ID.String(),
				"error":     err.Error(),
			})
		}
	}

	if err := h.refreshTokenRepo.RevokeByUserID(c.Context(), userID); err != nil {
		h.logger.Error(logging.Redis, logging.Delete, "Failed to revoke user refresh tokens", map[logging.ExtraKey]interface{}{
			"userID": userID.String(),
			"error":  err.Error(),
		})
	}

	return response.New().Data(fiber.Map{"message": "All sessions revoked for user"}).Send(c)
}
