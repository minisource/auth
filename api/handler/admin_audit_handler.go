package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
	"gorm.io/gorm"
)

// LoginLogEntry is a typed response for login log entries with user info
type LoginLogEntry struct {
	ID          uuid.UUID `json:"id"`
	UserID      uuid.UUID `json:"userId"`
	Action      string    `json:"action"`
	IPAddress   string    `json:"ipAddress"`
	UserAgent   string    `json:"userAgent"`
	Success     bool      `json:"success"`
	ErrorMsg    string    `json:"errorMsg"`
	CreatedAt   time.Time `json:"createdAt"`
	UserEmail   string    `json:"userEmail"`
	UserFirstName string  `json:"userFirstName"`
	UserLastName  string  `json:"userLastName"`
}

// AdminAuditHandler handles admin audit/log endpoints
type AdminAuditHandler struct {
	loginLogRepo repository.LoginLogRepository
	db           *gorm.DB
	logger       logging.Logger
}

func NewAdminAuditHandler(
	loginLogRepo repository.LoginLogRepository,
	db *gorm.DB,
	logger logging.Logger,
) *AdminAuditHandler {
	return &AdminAuditHandler{
		loginLogRepo: loginLogRepo,
		db:           db,
		logger:       logger,
	}
}

// ListLoginLogs godoc
// @Summary List login logs
// @Description Get login/logout activity logs with ordering
// @Tags Admin/Audit
// @Produce json
// @Param action query string false "Filter by action (login, login_failed, logout, etc.)"
// @Param search query string false "Search by email, name, IP, or user agent"
// @Param orderBy query string false "Sort field (createdAt, action, ipAddress)" default(createdAt)
// @Param sort query string false "Sort direction (asc, desc)" default(desc)
// @Param limit query int false "Limit results" default(50)
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/login-logs [get]
func (h *AdminAuditHandler) ListLoginLogs(c *fiber.Ctx) error {
	action := c.Query("action")
	search := c.Query("search")
	orderBy := c.Query("orderBy", "createdAt")
	sort := c.Query("sort", "desc")
	limit := c.QueryInt("limit", 50)

	if limit < 1 || limit > 200 {
		limit = 50
	}

	var logs []LoginLogEntry

	query := h.db.WithContext(c.Context()).Table("login_logs").
		Select("login_logs.id, login_logs.user_id, login_logs.action, login_logs.ip_address, login_logs.user_agent, login_logs.success, login_logs.error_msg, login_logs.created_at, COALESCE(users.email, '') as user_email, COALESCE(users.first_name, '') as user_first_name, COALESCE(users.last_name, '') as user_last_name").
		Joins("LEFT JOIN users ON users.id = login_logs.user_id")

	if action != "" {
		query = query.Where("login_logs.action = ?", action)
	}

	if search != "" {
		pattern := "%" + search + "%"
		query = query.Where(
			"users.email ILIKE ? OR users.first_name ILIKE ? OR users.last_name ILIKE ? OR login_logs.ip_address ILIKE ? OR login_logs.user_agent ILIKE ?",
			pattern, pattern, pattern, pattern, pattern,
		)
	}

	orderByCol := "login_logs.created_at"
	switch orderBy {
	case "action":
		orderByCol = "login_logs.action"
	case "ipAddress", "ip_address":
		orderByCol = "login_logs.ip_address"
	case "success":
		orderByCol = "login_logs.success"
	case "createdAt", "created_at", "":
		orderByCol = "login_logs.created_at"
	}

	sortDir := "DESC"
	if sort == "asc" {
		sortDir = "ASC"
	}

	query = query.Order(orderByCol + " " + sortDir).Limit(limit)

	result := query.Scan(&logs)
	if result.Error != nil {
		return response.InternalError(c, "Failed to fetch login logs")
	}

	return response.New().Data(logs).Send(c)
}

// ListAuditLogs godoc
// @Summary List audit logs
// @Description Get audit trail of admin actions
// @Tags Admin/Audit
// @Produce json
// @Param limit query int false "Limit results" default(50)
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/audit-logs [get]
func (h *AdminAuditHandler) ListAuditLogs(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 50)

	if limit < 1 || limit > 200 {
		limit = 50
	}

	var logs []map[string]interface{}

	// Check if audit_logs table exists
	if h.db.Migrator().HasTable("audit_logs") {
		result := h.db.WithContext(c.Context()).Table("audit_logs").
			Order("created_at DESC").
			Limit(limit).
			Find(&logs)
		if result.Error != nil {
			// Table exists but query failed
			return response.New().Data([]interface{}{}).Send(c)
		}
	}

	return response.New().Data(logs).Send(c)
}
