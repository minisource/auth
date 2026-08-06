package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/retention"
	"gorm.io/gorm"
)

// AuthRunner implements safe, cursor-based batch deletion for Auth log tables.
type AuthRunner struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewAuthRunner(db *gorm.DB, logger logging.Logger) *AuthRunner {
	return &AuthRunner{db: db, logger: logger}
}

// ComputeCountCutoff queries the DB for the created_at timestamp of the
// Nth newest record (where N = keepLatest). Records older than this
// threshold are eligible for count-based cleanup.
// Returns a zero time if keepLatest <= 0 or no records exist.
func (r *AuthRunner) ComputeCountCutoff(ctx context.Context, category string, keepLatest int) (time.Time, error) {
	if keepLatest <= 0 {
		return time.Time{}, nil
	}
	var row struct{ CreatedAt time.Time }
	err := r.db.WithContext(ctx).
		Table(category).
		Select("created_at").
		Order("created_at DESC, id DESC").
		Offset(keepLatest - 1).
		Limit(1).
		Scan(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return time.Time{}, nil // fewer than N records exist
		}
		return time.Time{}, fmt.Errorf("compute count cutoff for %s: %w", category, err)
	}
	return row.CreatedAt, nil
}

// NewSharedRunner builds a retention.BatchRunner wired to the correct delete
// function for the given category.
func (r *AuthRunner) NewSharedRunner(snapshot retention.RunSnapshot) (*retention.BatchRunner, error) {
	switch snapshot.Category {
	case CategoryLoginLogs.String():
		return retention.NewBatchRunner(snapshot, r.loginLogsEligibility, r.loginLogsDelete), nil
	case CategorySessions.String():
		return retention.NewBatchRunner(snapshot, r.sessionsEligibility, r.sessionsDelete), nil
	default:
		return nil, fmt.Errorf("%w: %s", retention.ErrCategoryProtected, snapshot.Category)
	}
}

// ── login_logs ───────────────────────────────────────────────────────

func (r *AuthRunner) loginLogsEligibility(ctx context.Context, snapshot retention.RunSnapshot) (int64, error) {
	var count int64
	q := r.db.WithContext(ctx).Model(&models.LoginLog{}).
		Where("created_at < ?", snapshot.Cutoff)
	if err := q.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("login_logs eligibility: %w", err)
	}
	return count, nil
}

func (r *AuthRunner) loginLogsDelete(ctx context.Context, snapshot retention.RunSnapshot, lastCreatedAt time.Time, lastID uuid.UUID) (deleted int64, newLastCreatedAt time.Time, newLastID uuid.UUID, hasMore bool, err error) {
	// Cursor-based: WHERE (created_at, id) > (lastCreatedAt, lastID) AND created_at < cutoff
	// ORDER BY created_at ASC, id ASC LIMIT batchSize
	var ids []struct {
		ID        uuid.UUID
		CreatedAt time.Time
	}

	q := r.db.WithContext(ctx).Model(&models.LoginLog{}).
		Select("id, created_at").
		Where("created_at < ?", snapshot.Cutoff).
		Order("created_at ASC, id ASC").
		Limit(snapshot.BatchSize)

	if lastID != uuid.Nil {
		q = q.Where("(created_at, id) > (?, ?)", lastCreatedAt, lastID.String())
	}

	if err := q.Find(&ids).Error; err != nil {
		return 0, time.Time{}, uuid.Nil, false, fmt.Errorf("login_logs cursor query: %w", err)
	}
	if len(ids) == 0 {
		return 0, time.Time{}, uuid.Nil, false, nil
	}

	// Collect IDs and delete
	idList := make([]uuid.UUID, len(ids))
	for i, row := range ids {
		idList[i] = row.ID
	}

	res := r.db.WithContext(ctx).Where("id IN ?", idList).Delete(&models.LoginLog{})
	if res.Error != nil {
		return 0, time.Time{}, uuid.Nil, false, fmt.Errorf("login_logs delete: %w", res.Error)
	}

	last := ids[len(ids)-1]
	return res.RowsAffected, last.CreatedAt, last.ID, len(ids) == snapshot.BatchSize, nil
}

// ── sessions (expired+revoked only) ──────────────────────────────────

func (r *AuthRunner) sessionsEligibility(ctx context.Context, snapshot retention.RunSnapshot) (int64, error) {
	var count int64
	q := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("created_at < ?", snapshot.Cutoff).
		Where("(is_active = false AND revoked_at IS NOT NULL)")
	if err := q.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("sessions eligibility: %w", err)
	}
	return count, nil
}

func (r *AuthRunner) sessionsDelete(ctx context.Context, snapshot retention.RunSnapshot, lastCreatedAt time.Time, lastID uuid.UUID) (deleted int64, newLastCreatedAt time.Time, newLastID uuid.UUID, hasMore bool, err error) {
	var ids []struct {
		ID        uuid.UUID
		CreatedAt time.Time
	}

	q := r.db.WithContext(ctx).Model(&models.Session{}).
		Select("id, created_at").
		Where("created_at < ?", snapshot.Cutoff).
		Where("is_active = false AND revoked_at IS NOT NULL").
		Order("created_at ASC, id ASC").
		Limit(snapshot.BatchSize)

	if lastID != uuid.Nil {
		q = q.Where("(created_at, id) > (?, ?)", lastCreatedAt, lastID.String())
	}

	if err := q.Find(&ids).Error; err != nil {
		return 0, time.Time{}, uuid.Nil, false, fmt.Errorf("sessions cursor query: %w", err)
	}
	if len(ids) == 0 {
		return 0, time.Time{}, uuid.Nil, false, nil
	}

	idList := make([]uuid.UUID, len(ids))
	for i, row := range ids {
		idList[i] = row.ID
	}

	res := r.db.WithContext(ctx).Where("id IN ?", idList).Delete(&models.Session{})
	if res.Error != nil {
		return 0, time.Time{}, uuid.Nil, false, fmt.Errorf("sessions delete: %w", res.Error)
	}

	last := ids[len(ids)-1]
	return res.RowsAffected, last.CreatedAt, last.ID, len(ids) == snapshot.BatchSize, nil
}


