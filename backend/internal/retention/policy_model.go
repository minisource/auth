package retention

import (
	"time"

	"github.com/google/uuid"
	"github.com/minisource/go-common/retention"
	"gorm.io/gorm"
)

// PolicyModel is the database entity for a log retention policy.
type PolicyModel struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Service     string         `gorm:"size:50;not null;index:idx_retention_service_category" json:"service"`
	Category    string         `gorm:"size:100;not null;index:idx_retention_service_category" json:"category"`
	Enabled     bool           `gorm:"default:false;not null" json:"enabled"`
	Strategy    string         `gorm:"size:20;not null;default:'age'" json:"strategy"`
	Description string         `gorm:"size:1000" json:"description,omitempty"`

	RetentionDays   int        `gorm:"default:30" json:"retentionDays"`
	CutoffTimestamp *time.Time `json:"cutoffTimestamp,omitempty"`
	KeepLatestCount int        `gorm:"default:100000" json:"keepLatestCount"`

	CronExpression   string `gorm:"size:100" json:"cronExpression,omitempty"`
	Timezone         string `gorm:"size:50;default:'UTC'" json:"timezone"`
	BatchSize        int    `gorm:"default:500;not null" json:"batchSize"`
	MaxBatchesPerRun int    `gorm:"default:20;not null" json:"maxBatchesPerRun"`
	DryRun           bool   `gorm:"default:true;not null" json:"dryRun"`
	MinRetentionDays int    `gorm:"default:7;not null" json:"minRetentionDays"`

	CreatedAt time.Time      `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time      `gorm:"not null;default:now()" json:"updatedAt"`
	UpdatedBy string         `gorm:"size:255" json:"updatedBy,omitempty"`
	LastRunAt *time.Time     `json:"lastRunAt,omitempty"`
	NextRunAt *time.Time     `json:"nextRunAt,omitempty"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (PolicyModel) TableName() string { return "retention_policies" }

func (p *PolicyModel) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// ToDomain converts the DB model to the shared retention.Policy.
func (p *PolicyModel) ToDomain() retention.Policy {
	return retention.Policy{
		ID:               p.ID.String(),
		Service:          p.Service,
		Category:         p.Category,
		Enabled:          p.Enabled,
		Strategy:         retention.Strategy(p.Strategy),
		Description:      p.Description,
		RetentionDays:    p.RetentionDays,
		CutoffTimestamp:  p.CutoffTimestamp,
		KeepLatestCount:  p.KeepLatestCount,
		CronExpression:   p.CronExpression,
		Timezone:         p.Timezone,
		BatchSize:        p.BatchSize,
		MaxBatchesPerRun: p.MaxBatchesPerRun,
		DryRun:           p.DryRun,
		MinRetentionDays: p.MinRetentionDays,
		CreatedAt:        p.CreatedAt,
		UpdatedAt:        p.UpdatedAt,
		UpdatedBy:        p.UpdatedBy,
		LastRunAt:        p.LastRunAt,
		NextRunAt:        p.NextRunAt,
	}
}

// FromDomain populates the DB model from a shared retention.Policy.
func (p *PolicyModel) FromDomain(d *retention.Policy) {
	if d.ID != "" {
		if parsed, err := uuid.Parse(d.ID); err == nil {
			p.ID = parsed
		}
	}
	p.Service = d.Service
	p.Category = d.Category
	p.Enabled = d.Enabled
	p.Strategy = string(d.Strategy)
	p.Description = d.Description
	p.RetentionDays = d.RetentionDays
	p.CutoffTimestamp = d.CutoffTimestamp
	p.KeepLatestCount = d.KeepLatestCount
	p.CronExpression = d.CronExpression
	p.Timezone = d.Timezone
	p.BatchSize = d.BatchSize
	p.MaxBatchesPerRun = d.MaxBatchesPerRun
	p.DryRun = d.DryRun
	p.MinRetentionDays = d.MinRetentionDays
}
