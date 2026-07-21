package handler

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
	"gorm.io/gorm"
)

// dashboardStats holds aggregated dashboard statistics
type dashboardStats struct {
	totalUsers       int64
	activeUsers      int64
	lockedUsers      int64
	unverifiedEmail  int64
	rolesCount       int64
	permissionsCount int64
	tenantsCount     int64
	svcClientsCount  int64
	failedLogins24h  int64
	activeSessions   int64
	newUsersToday    int64
	newUsers7d       int64
}

// AdminDashboardHandler handles admin dashboard/stats endpoints
type AdminDashboardHandler struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewAdminDashboardHandler(
	db *gorm.DB,
	logger logging.Logger,
) *AdminDashboardHandler {
	return &AdminDashboardHandler{
		db:     db,
		logger: logger,
	}
}

// GetDashboardOverview godoc
// @Summary Get dashboard overview
// @Description Get system-wide stats for the admin dashboard
// @Tags Admin/Dashboard
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/dashboard/overview [get]
func (h *AdminDashboardHandler) GetDashboardOverview(c *fiber.Ctx) error {
	ctx := c.Context()

	stats := h.gatherStats(ctx)

	return response.New().Data(fiber.Map{
		"users": fiber.Map{
			"total":           stats.totalUsers,
			"active":          stats.activeUsers,
			"locked":          stats.lockedUsers,
			"unverifiedEmail": stats.unverifiedEmail,
			"newToday":        stats.newUsersToday,
			"newLast7Days":    stats.newUsers7d,
		},
		"accessControl": fiber.Map{
			"roles":       stats.rolesCount,
			"permissions": stats.permissionsCount,
		},
		"tenants": fiber.Map{
			"total": stats.tenantsCount,
		},
		"integrations": fiber.Map{
			"serviceClients": stats.svcClientsCount,
		},
		"security": fiber.Map{
			"activeSessions":  stats.activeSessions,
			"failedLogins24h": stats.failedLogins24h,
		},
	}).Send(c)
}

func (h *AdminDashboardHandler) gatherStats(ctx context.Context) dashboardStats {
	var result dashboardStats

	// Total users
	h.db.Model(&models.User{}).Count(&result.totalUsers)

	// Active users
	h.db.Model(&models.User{}).Where("is_active = true").Count(&result.activeUsers)

	// Locked users
	now := time.Now()
	h.db.Model(&models.User{}).Where("locked_until IS NOT NULL AND locked_until > ?", now).Count(&result.lockedUsers)

	// Unverified email users
	h.db.Model(&models.User{}).Where("email_verified = false AND email != ''").Count(&result.unverifiedEmail)

	// Roles
	h.db.Model(&models.Role{}).Count(&result.rolesCount)

	// Permissions
	h.db.Model(&models.Permission{}).Count(&result.permissionsCount)

	// Tenants
	h.db.Model(&models.Tenant{}).Count(&result.tenantsCount)

	// Service clients
	h.db.Model(&models.ServiceClient{}).Count(&result.svcClientsCount)

	// Failed logins in last 24h
	since := time.Now().Add(-24 * time.Hour)
	h.db.Model(&models.LoginLog{}).
		Where("action = ? AND success = false AND created_at > ?", models.LoginActionLoginFailed, since).
		Count(&result.failedLogins24h)

	// Active sessions
	h.db.Model(&models.Session{}).Where("is_active = true AND expires_at > ?", now).Count(&result.activeSessions)

	// New users today
	today := time.Now().Truncate(24 * time.Hour)
	h.db.Model(&models.User{}).Where("created_at > ?", today).Count(&result.newUsersToday)

	// New users in last 7 days
	weekAgo := time.Now().Add(-7 * 24 * time.Hour)
	h.db.Model(&models.User{}).Where("created_at > ?", weekAgo).Count(&result.newUsers7d)

	return result
}

// GetRecentActivity godoc
// @Summary Get recent login activity
// @Description Get recent login activity for the dashboard
// @Tags Admin/Dashboard
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/dashboard/recent-activity [get]
func (h *AdminDashboardHandler) GetRecentActivity(c *fiber.Ctx) error {
	ctx := c.Context()

	var recentLogs []models.LoginLog
	h.db.WithContext(ctx).
		Preload("User").
		Order("created_at DESC").
		Limit(20).
		Find(&recentLogs)

	activities := make([]map[string]interface{}, 0)
	for _, log := range recentLogs {
		activities = append(activities, map[string]interface{}{
			"id":        log.ID.String(),
			"userId":    log.UserID.String(),
			"action":    log.Action,
			"success":   log.Success,
			"ipAddress": log.IPAddress,
			"userAgent": log.UserAgent,
			"createdAt": log.CreatedAt,
		})
	}

	return response.New().Data(activities).Send(c)
}
