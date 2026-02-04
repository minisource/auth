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
	Update(ctx context.Context, session *models.Session) error
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
	// Redis operations
	CacheSession(ctx context.Context, session *models.Session, expiry time.Duration) error
	GetCachedSession(ctx context.Context, sessionID string) (*models.Session, error)
	InvalidateCachedSession(ctx context.Context, sessionID string) error
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
