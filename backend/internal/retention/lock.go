package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/minisource/go-common/retention"
	"gorm.io/gorm"
)

// PGLock implements retention.DistributedLock using PostgreSQL advisory locks.
// Advisory locks are automatically released when the session/connection ends,
// making them safe for process crashes.
type PGLock struct {
	db *gorm.DB
}

func NewPGLock(db *gorm.DB) *PGLock {
	return &PGLock{db: db}
}

// lockKey returns a deterministic int64 key for the given lock key string.
// We use pg_try_advisory_lock with a hash of the key.
func lockKey(key string) int64 {
	var h int64
	for _, c := range key {
		h = h*31 + int64(c)
	}
	return h
}

func (l *PGLock) Acquire(ctx context.Context, key string, ttl time.Duration) (retention.LockGuard, error) {
	k := lockKey(key)

	var acquired bool
	err := l.db.WithContext(ctx).Raw("SELECT pg_try_advisory_lock(?)", k).Scan(&acquired).Error
	if err != nil {
		return nil, fmt.Errorf("pg advisory lock acquire: %w", err)
	}
	if !acquired {
		return nil, retention.ErrLockHeld
	}

	return &pgLockGuard{db: l.db, key: k, lockKey: key}, nil
}

func (l *PGLock) IsHeld(ctx context.Context, key string) (bool, error) {
	k := lockKey(key)
	// pg_try_advisory_lock would fail if held; but we use a non-blocking query
	// that just checks. There's no direct "is it held?" function, so we try-lock
	// and immediately release.
	var acquired bool
	err := l.db.WithContext(ctx).Raw("SELECT pg_try_advisory_lock(?)", k).Scan(&acquired).Error
	if err != nil {
		return false, err
	}
	if acquired {
		// Release immediately — this was just a test
		_ = l.db.WithContext(ctx).Exec("SELECT pg_advisory_unlock(?)", k).Error
		return false, nil
	}
	return true, nil
}

type pgLockGuard struct {
	db      *gorm.DB
	key     int64
	lockKey string
}

func (g *pgLockGuard) Release(ctx context.Context) error {
	err := g.db.WithContext(ctx).Exec("SELECT pg_advisory_unlock(?)", g.key).Error
	if err != nil {
		return fmt.Errorf("pg advisory lock release: %w", err)
	}
	return nil
}

func (g *pgLockGuard) Key() string { return g.lockKey }

// LockKey builds the canonical lock key for a (service, category) pair.
func LockKey(service, category string) string {
	return fmt.Sprintf("retention:%s:%s", service, category)
}

// Assert: PGLock satisfies the interface.
var _ retention.DistributedLock = (*PGLock)(nil)
