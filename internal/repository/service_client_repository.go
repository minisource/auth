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

type ServiceClientRepository interface {
	Create(ctx context.Context, client *models.ServiceClient) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceClient, error)
	GetByClientID(ctx context.Context, clientID string) (*models.ServiceClient, error)
	GetByName(ctx context.Context, name string) (*models.ServiceClient, error)
	Update(ctx context.Context, client *models.ServiceClient) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]models.ServiceClient, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
	// Redis operations for service tokens
	CacheServiceToken(ctx context.Context, clientID, token string, expiry time.Duration) error
	GetCachedServiceToken(ctx context.Context, clientID string) (string, error)
	InvalidateServiceToken(ctx context.Context, clientID string) error
	BlacklistToken(ctx context.Context, token string, expiry time.Duration) error
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)
}

type serviceClientRepository struct {
	db     *gorm.DB
	redis  *redis.Client
	logger logging.Logger
}

func NewServiceClientRepository(db *gorm.DB, redis *redis.Client, logger logging.Logger) ServiceClientRepository {
	return &serviceClientRepository{db: db, redis: redis, logger: logger}
}

func (r *serviceClientRepository) Create(ctx context.Context, client *models.ServiceClient) error {
	return r.db.WithContext(ctx).Create(client).Error
}

func (r *serviceClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceClient, error) {
	var client models.ServiceClient
	result := r.db.WithContext(ctx).First(&client, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &client, nil
}

func (r *serviceClientRepository) GetByClientID(ctx context.Context, clientID string) (*models.ServiceClient, error) {
	var client models.ServiceClient
	result := r.db.WithContext(ctx).First(&client, "client_id = ?", clientID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &client, nil
}

func (r *serviceClientRepository) GetByName(ctx context.Context, name string) (*models.ServiceClient, error) {
	var client models.ServiceClient
	result := r.db.WithContext(ctx).First(&client, "name = ?", name)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &client, nil
}

func (r *serviceClientRepository) Update(ctx context.Context, client *models.ServiceClient) error {
	return r.db.WithContext(ctx).Save(client).Error
}

func (r *serviceClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.ServiceClient{}, "id = ?", id).Error
}

func (r *serviceClientRepository) List(ctx context.Context) ([]models.ServiceClient, error) {
	var clients []models.ServiceClient
	result := r.db.WithContext(ctx).Where("is_active = true").Find(&clients)
	return clients, result.Error
}

func (r *serviceClientRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.ServiceClient{}).Where("id = ?", id).
		Update("last_used_at", now).Error
}

// Redis key for service tokens
const redisKeyServiceToken = "service_token:"

func (r *serviceClientRepository) CacheServiceToken(ctx context.Context, clientID, token string, expiry time.Duration) error {
	key := redisKeyServiceToken + clientID
	return r.redis.Set(ctx, key, token, expiry).Err()
}

func (r *serviceClientRepository) GetCachedServiceToken(ctx context.Context, clientID string) (string, error) {
	key := redisKeyServiceToken + clientID
	token, err := r.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return token, err
}

func (r *serviceClientRepository) InvalidateServiceToken(ctx context.Context, clientID string) error {
	key := redisKeyServiceToken + clientID
	return r.redis.Del(ctx, key).Err()
}

// Blacklist token in Redis
func (r *serviceClientRepository) BlacklistToken(ctx context.Context, token string, expiry time.Duration) error {
	key := database.BlacklistKey(token)
	return r.redis.Set(ctx, key, "1", expiry).Err()
}

func (r *serviceClientRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	key := database.BlacklistKey(token)
	exists, err := r.redis.Exists(ctx, key).Result()
	return exists > 0, err
}
