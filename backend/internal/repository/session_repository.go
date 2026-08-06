package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/database"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	GetByAccessToken(ctx context.Context, token string) (*models.Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]models.Session, error)
	ListAll(ctx context.Context, filter SessionListFilter) ([]SessionWithUser, int64, error)
	Update(ctx context.Context, session *models.Session) error
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
	// Redis operations
	CacheSession(ctx context.Context, session *models.Session, expiry time.Duration) error
	GetCachedSession(ctx context.Context, sessionID string) (*models.Session, error)
	InvalidateCachedSession(ctx context.Context, sessionID string) error
}

// SessionListFilter controls admin session listing.
type SessionListFilter struct {
	TenantID *uuid.UUID
	Search   string
	UserID   *uuid.UUID
	IsActive *bool
	OrderBy  string
	Sort     string
	Limit    int
	Offset   int
}

// SessionWithUser is a session row enriched with user identity fields.
type SessionWithUser struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      *uuid.UUID `json:"tenantId,omitempty"`
	UserID        uuid.UUID  `json:"userId"`
	UserAgent     string     `json:"userAgent,omitempty"`
	IPAddress     string     `json:"ipAddress,omitempty"`
	DeviceType    string     `json:"deviceType,omitempty"`
	IsActive      bool       `json:"isActive"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	LastActiveAt  time.Time  `json:"lastActiveAt"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	UserEmail     string     `json:"userEmail"`
	UserFirstName string     `json:"userFirstName"`
	UserLastName  string     `json:"userLastName"`
}

type sessionRepository struct {
	db     *gorm.DB
	redis  *redis.Client
	logger logging.Logger
}

func NewSessionRepository(db *gorm.DB, redis *redis.Client, logger logging.Logger) SessionRepository {
	return &sessionRepository{db: db, redis: redis, logger: logger}
}

func (r *sessionRepository) Create(ctx context.Context, session *models.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *sessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	var session models.Session
	result := r.db.WithContext(ctx).First(&session, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &session, nil
}

func (r *sessionRepository) GetByAccessToken(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	result := r.db.WithContext(ctx).First(&session, "access_token = ? AND is_active = true", token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &session, nil
}

func (r *sessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	var sessions []models.Session
	result := r.db.WithContext(ctx).Where("user_id = ? AND is_active = true", userID).
		Order("created_at DESC").Find(&sessions)
	return sessions, result.Error
}

func (r *sessionRepository) ListAll(ctx context.Context, filter SessionListFilter) ([]SessionWithUser, int64, error) {
	buildQuery := func() *gorm.DB {
		q := r.db.WithContext(ctx).Table("sessions").
			Joins("LEFT JOIN users ON users.id = sessions.user_id")

		if filter.Search != "" {
			pattern := "%" + filter.Search + "%"
			q = q.Where(
				"users.email ILIKE ? OR users.first_name ILIKE ? OR users.last_name ILIKE ? OR sessions.ip_address ILIKE ? OR sessions.user_agent ILIKE ? OR CAST(sessions.user_id AS TEXT) ILIKE ?",
				pattern, pattern, pattern, pattern, pattern, pattern,
			)
		}
		if filter.UserID != nil {
			q = q.Where("sessions.user_id = ?", *filter.UserID)
		}
		if filter.IsActive != nil {
			q = q.Where("sessions.is_active = ?", *filter.IsActive)
		}
		return q
	}

	var total int64
	if err := buildQuery().Count(&total).Error; err != nil {
		return nil, 0, err
	}

	orderBy := "sessions.created_at"
	switch filter.OrderBy {
	case "lastActiveAt", "last_active_at":
		orderBy = "sessions.last_active_at"
	case "expiresAt", "expires_at":
		orderBy = "sessions.expires_at"
	case "ipAddress", "ip_address":
		orderBy = "sessions.ip_address"
	case "createdAt", "created_at", "":
		orderBy = "sessions.created_at"
	}

	sortDir := "DESC"
	if filter.Sort == "asc" {
		sortDir = "ASC"
	}

	var sessions []SessionWithUser
	result := buildQuery().
		Select(`sessions.id, sessions.tenant_id, sessions.user_id, sessions.user_agent, sessions.ip_address,
			sessions.device_type, sessions.is_active, sessions.expires_at, sessions.last_active_at,
			sessions.revoked_at, sessions.created_at, sessions.updated_at,
			COALESCE(users.email, '') AS user_email,
			COALESCE(users.first_name, '') AS user_first_name,
			COALESCE(users.last_name, '') AS user_last_name`).
		Order(orderBy + " " + sortDir).
		Limit(filter.Limit).
		Offset(filter.Offset).
		Scan(&sessions)

	if result.Error != nil {
		return nil, 0, result.Error
	}

	return sessions, total, nil
}

func (r *sessionRepository) Update(ctx context.Context, session *models.Session) error {
	return r.db.WithContext(ctx).Save(session).Error
}

func (r *sessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.Session{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"is_active":  false,
			"revoked_at": now,
		}).Error
}

func (r *sessionRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.Session{}).Where("user_id = ? AND is_active = true", userID).
		Updates(map[string]interface{}{
			"is_active":  false,
			"revoked_at": now,
		}).Error
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Session{}).Error
}

// Redis operations
func (r *sessionRepository) CacheSession(ctx context.Context, session *models.Session, expiry time.Duration) error {
	key := database.SessionKey(session.ID.String())
	data := map[string]interface{}{
		"user_id":    session.UserID.String(),
		"is_active":  session.IsActive,
		"expires_at": session.ExpiresAt.Unix(),
	}
	return r.redis.HSet(ctx, key, data).Err()
}

func (r *sessionRepository) GetCachedSession(ctx context.Context, sessionID string) (*models.Session, error) {
	key := database.SessionKey(sessionID)
	exists, err := r.redis.Exists(ctx, key).Result()
	if err != nil || exists == 0 {
		return nil, err
	}

	data, err := r.redis.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, nil
	}

	id, _ := uuid.Parse(sessionID)
	userID, _ := uuid.Parse(data["user_id"])

	return &models.Session{
		ID:       id,
		UserID:   userID,
		IsActive: data["is_active"] == "1",
	}, nil
}

func (r *sessionRepository) InvalidateCachedSession(ctx context.Context, sessionID string) error {
	key := database.SessionKey(sessionID)
	return r.redis.Del(ctx, key).Err()
}
