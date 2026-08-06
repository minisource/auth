package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/retention"
	"gorm.io/gorm"
)

// PolicyRepository persists and queries retention policies.
type PolicyRepository interface {
	List(ctx context.Context) ([]PolicyModel, error)
	GetByID(ctx context.Context, id uuid.UUID) (*PolicyModel, error)
	GetByCategory(ctx context.Context, category string) (*PolicyModel, error)
	Create(ctx context.Context, p *PolicyModel) error
	Update(ctx context.Context, p *PolicyModel) error
	Delete(ctx context.Context, id uuid.UUID) error

	// ListEnabled returns only policies that are enabled AND have a configured
	// cron expression. These are the policies the scheduler should tick.
	ListEnabled(ctx context.Context) ([]PolicyModel, error)
}

type policyRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewPolicyRepository(db *gorm.DB, logger logging.Logger) PolicyRepository {
	return &policyRepository{db: db, logger: logger}
}

func (r *policyRepository) List(ctx context.Context) ([]PolicyModel, error) {
	var policies []PolicyModel
	result := r.db.WithContext(ctx).Order("created_at DESC").Find(&policies)
	return policies, result.Error
}

func (r *policyRepository) GetByID(ctx context.Context, id uuid.UUID) (*PolicyModel, error) {
	var p PolicyModel
	result := r.db.WithContext(ctx).First(&p, "id = ?", id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &p, nil
}

func (r *policyRepository) GetByCategory(ctx context.Context, category string) (*PolicyModel, error) {
	var p PolicyModel
	result := r.db.WithContext(ctx).
		Where("service = ? AND category = ?", ServiceName, category).
		First(&p)
	if result.Error != nil {
		return nil, result.Error
	}
	return &p, nil
}

func (r *policyRepository) Create(ctx context.Context, p *PolicyModel) error {
	p.Service = ServiceName
	return r.db.WithContext(ctx).Create(p).Error
}

func (r *policyRepository) Update(ctx context.Context, p *PolicyModel) error {
	return r.db.WithContext(ctx).Save(p).Error
}

func (r *policyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&PolicyModel{}, "id = ?", id).Error
}

func (r *policyRepository) ListEnabled(ctx context.Context) ([]PolicyModel, error) {
	var policies []PolicyModel
	result := r.db.WithContext(ctx).
		Where("service = ? AND enabled = true AND cron_expression IS NOT NULL AND cron_expression != ''", ServiceName).
		Find(&policies)
	if result.Error != nil {
		return nil, fmt.Errorf("list enabled policies: %w", result.Error)
	}
	return policies, nil
}

// ── RunRecord ────────────────────────────────────────────────────────

// RunRecord is the database entity for a cleanup execution record.
type RunRecord struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PolicyID     uuid.UUID  `gorm:"type:uuid;not null;index" json:"policyId"`
	Service      string     `gorm:"size:50;not null" json:"service"`
	Category     string     `gorm:"size:100;not null;index" json:"category"`
	Trigger      string     `gorm:"size:20;not null" json:"trigger"` // scheduled | manual
	Strategy     string     `gorm:"size:20;not null" json:"strategy"`
	DryRun       bool       `gorm:"not null" json:"dryRun"`
	Result       string     `gorm:"size:30;not null" json:"result"`
	ScannedCount int64      `json:"scannedCount"`
	DeletedCount int64      `json:"deletedCount"`
	BatchesRun   int        `json:"batchesRun"`
	ErrorMsg     string     `gorm:"size:2000" json:"errorMsg,omitempty"`
	StartedAt    time.Time  `gorm:"not null;index" json:"startedAt"`
	EndedAt      *time.Time `json:"endedAt,omitempty"`
	CreatedAt    time.Time  `gorm:"not null;default:now()" json:"createdAt"`
}

func (RunRecord) TableName() string { return "retention_runs" }

func (r *RunRecord) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// RunRepository persists cleanup execution records.
type RunRepository interface {
	Create(ctx context.Context, r *RunRecord) error
	List(ctx context.Context, limit int) ([]RunRecord, error)
	GetByID(ctx context.Context, id uuid.UUID) (*RunRecord, error)
}

type runRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewRunRepository(db *gorm.DB, logger logging.Logger) RunRepository {
	return &runRepository{db: db, logger: logger}
}

func (r *runRepository) Create(ctx context.Context, rec *RunRecord) error {
	return r.db.WithContext(ctx).Create(rec).Error
}

func (r *runRepository) List(ctx context.Context, limit int) ([]RunRecord, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	var records []RunRecord
	result := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Find(&records)
	return records, result.Error
}

func (r *runRepository) GetByID(ctx context.Context, id uuid.UUID) (*RunRecord, error) {
	var rec RunRecord
	result := r.db.WithContext(ctx).First(&rec, "id = ?", id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &rec, nil
}

// RecordRun creates an immutable RunRecord from a cleanup result.
func RecordRun(ctx context.Context, repo RunRepository, snapshot retention.RunSnapshot, result retention.RunResult) (*RunRecord, error) {
	policyID, _ := uuid.Parse(snapshot.PolicyID)
	rec := &RunRecord{
		PolicyID:     policyID,
		Service:      snapshot.Service,
		Category:     snapshot.Category,
		Trigger:      string(snapshot.Trigger),
		Strategy:     string(snapshot.Strategy),
		DryRun:       snapshot.DryRun,
		Result:       string(result.Result),
		ScannedCount: result.ScannedCount,
		DeletedCount: result.DeletedCount,
		BatchesRun:   result.BatchesRun,
		StartedAt:    result.StartedAt,
	}
	if result.Error != nil {
		rec.ErrorMsg = result.Error.Error()
		// Truncate to DB column size
		if len(rec.ErrorMsg) > 2000 {
			rec.ErrorMsg = rec.ErrorMsg[:2000]
		}
	}
	endedAt := result.EndedAt
	rec.EndedAt = &endedAt

	if err := repo.Create(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
}
