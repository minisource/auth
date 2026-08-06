package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/internal/retention"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
	sharedRetention "github.com/minisource/go-common/retention"
)

// AdminRetentionHandler manages log retention policy endpoints.
type AdminRetentionHandler struct {
	policyRepo retention.PolicyRepository
	runRepo    retention.RunRepository
	scheduler  *retention.Scheduler
	logger     logging.Logger
}

func NewAdminRetentionHandler(
	policyRepo retention.PolicyRepository,
	runRepo retention.RunRepository,
	scheduler *retention.Scheduler,
	logger logging.Logger,
) *AdminRetentionHandler {
	return &AdminRetentionHandler{
		policyRepo: policyRepo,
		runRepo:    runRepo,
		scheduler:  scheduler,
		logger:     logger,
	}
}

// ── Policies ─────────────────────────────────────────────────────────

func (h *AdminRetentionHandler) ListPolicies(c *fiber.Ctx) error {
	policies, err := h.policyRepo.List(c.Context())
	if err != nil {
		return response.InternalError(c, "Failed to list retention policies")
	}
	dtos := make([]map[string]interface{}, len(policies))
	for i, p := range policies {
		dtos[i] = policyToDTO(&p)
	}
	return response.New().Data(dtos).Send(c)
}

func (h *AdminRetentionHandler) GetPolicy(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid policy ID")
	}
	p, err := h.policyRepo.GetByID(c.Context(), id)
	if err != nil {
		return response.NotFound(c, "Policy not found")
	}
	return response.New().Data(policyToDTO(p)).Send(c)
}

func (h *AdminRetentionHandler) UpsertPolicy(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid policy ID")
	}

	var req PolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}
	if req.Category == "" {
		return response.BadRequest(c, "VALIDATION_ERROR", "Category is required")
	}
	if req.Strategy == "" {
		req.Strategy = "age"
	}
	if req.RetentionDays == 0 && req.Strategy == "age" {
		req.RetentionDays = 30
	}
	if req.KeepLatestCount == 0 && req.Strategy == "count" {
		req.KeepLatestCount = 100000
	}
	if req.BatchSize == 0 {
		req.BatchSize = 500
	}
	if req.MaxBatchesPerRun == 0 {
		req.MaxBatchesPerRun = 20
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	// Build shared domain policy
	domain := sharedRetention.Policy{
		ID:               id.String(),
		Service:          retention.ServiceName,
		Category:         req.Category,
		Enabled:          req.Enabled,
		Strategy:         sharedRetention.Strategy(req.Strategy),
		Description:      req.Description,
		RetentionDays:    req.RetentionDays,
		KeepLatestCount:  req.KeepLatestCount,
		CronExpression:   req.CronExpression,
		Timezone:         req.Timezone,
		BatchSize:        req.BatchSize,
		MaxBatchesPerRun: req.MaxBatchesPerRun,
		DryRun:           req.DryRun,
		UpdatedBy:        getActor(c),
	}

	existing, err := h.policyRepo.GetByID(c.Context(), id)
	if err != nil {
		// Create
		model := &retention.PolicyModel{}
		model.FromDomain(&domain)
		if meta := retention.GetMeta(req.Category); meta != nil {
			model.MinRetentionDays = meta.MinRetentionDays
		}
		if err := h.policyRepo.Create(c.Context(), model); err != nil {
			return response.InternalError(c, "Failed to create retention policy")
		}
		h.logAudit(c, "CREATE", model.Category)
		return response.New().Data(policyToDTO(model)).Send(c)
	}

	// Update
	existing.FromDomain(&domain)
	if meta := retention.GetMeta(req.Category); meta != nil {
		existing.MinRetentionDays = meta.MinRetentionDays
	}
	existing.UpdatedBy = getActor(c)
	existing.UpdatedAt = time.Now().UTC()
	if err := h.policyRepo.Update(c.Context(), existing); err != nil {
		return response.InternalError(c, "Failed to update retention policy")
	}
	h.logAudit(c, "UPDATE", existing.Category)
	return response.New().Data(policyToDTO(existing)).Send(c)
}

func (h *AdminRetentionHandler) EnablePolicy(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid policy ID")
	}
	p, err := h.policyRepo.GetByID(c.Context(), id)
	if err != nil {
		return response.NotFound(c, "Policy not found")
	}
	p.Enabled = true
	p.UpdatedBy = getActor(c)
	p.UpdatedAt = time.Now().UTC()
	if err := h.policyRepo.Update(c.Context(), p); err != nil {
		return response.InternalError(c, "Failed to enable policy")
	}
	return response.New().Data(policyToDTO(p)).Send(c)
}

func (h *AdminRetentionHandler) DisablePolicy(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid policy ID")
	}
	p, err := h.policyRepo.GetByID(c.Context(), id)
	if err != nil {
		return response.NotFound(c, "Policy not found")
	}
	p.Enabled = false
	p.UpdatedBy = getActor(c)
	p.UpdatedAt = time.Now().UTC()
	if err := h.policyRepo.Update(c.Context(), p); err != nil {
		return response.InternalError(c, "Failed to disable policy")
	}
	return response.New().Data(policyToDTO(p)).Send(c)
}

// ── Preview ──────────────────────────────────────────────────────────

func (h *AdminRetentionHandler) PreviewCleanup(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid policy ID")
	}
	p, err := h.policyRepo.GetByID(c.Context(), id)
	if err != nil {
		return response.NotFound(c, "Policy not found")
	}

	domain := p.ToDomain()
	if err := retention.ValidatePolicy(&domain); err != nil {
		return response.BadRequest(c, "INVALID_POLICY", err.Error())
	}

	cutoff := domain.ComputeCutoff(time.Now().UTC())
	snapshot := sharedRetention.RunSnapshot{
		PolicyID:   domain.ID,
		Service:    domain.Service,
		Category:   domain.Category,
		Strategy:   domain.Strategy,
		DryRun:     true,
		Cutoff:     cutoff,
		KeepLatest: domain.KeepLatestCount,
		BatchSize:  domain.EffectiveBatchSize(),
		MaxBatches: 1,
		Trigger:    sharedRetention.TriggerManual,
		RunID:      "preview-" + uuid.New().String(),
		StartedAt:  time.Now().UTC(),
	}

	sharedRunner, err := h.scheduler.GetRunner().NewSharedRunner(snapshot)
	if err != nil {
		return response.BadRequest(c, "INVALID_CATEGORY", "Cannot create runner for this category")
	}

	result := sharedRunner.Run(c.Context())

	return response.New().Data(map[string]interface{}{
		"category":         p.Category,
		"strategy":         p.Strategy,
		"retentionDays":    p.RetentionDays,
		"keepLatestCount":  p.KeepLatestCount,
		"cutoff":           cutoff.Format(time.RFC3339),
		"estimatedCount":   result.ScannedCount,
		"isDryRun":         true,
		"willDelete":       false,
		"minRetentionDays": p.MinRetentionDays,
	}).Send(c)
}

// ── Manual Run ───────────────────────────────────────────────────────

func (h *AdminRetentionHandler) RunCleanup(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid policy ID")
	}

	var req RunRequest
	_ = c.BodyParser(&req)

	if req.Confirm != "DELETE" {
		p, err := h.policyRepo.GetByID(c.Context(), id)
		if err != nil {
			return response.NotFound(c, "Policy not found")
		}
		return response.New().Status(fiber.StatusPreconditionRequired).Data(map[string]interface{}{
			"message":       "Confirmation required. Set 'confirm' to 'DELETE' to proceed.",
			"category":      p.Category,
			"strategy":      p.Strategy,
			"dryRun":        p.DryRun,
			"retentionDays": p.RetentionDays,
		}).Send(c)
	}

	p, err := h.policyRepo.GetByID(c.Context(), id)
	if err != nil {
		return response.NotFound(c, "Policy not found")
	}

	record, err := h.scheduler.ExecuteManual(c.Context(), *p)
	if err != nil {
		return response.InternalError(c, "Cleanup execution failed: "+err.Error())
	}
	return response.New().Data(runRecordToDTO(record)).Send(c)
}

// ── Run History ──────────────────────────────────────────────────────

func (h *AdminRetentionHandler) ListRuns(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 50)
	records, err := h.runRepo.List(c.Context(), limit)
	if err != nil {
		return response.InternalError(c, "Failed to list run history")
	}
	dtos := make([]map[string]interface{}, len(records))
	for i, r := range records {
		dtos[i] = runRecordToDTO(&r)
	}
	return response.New().Data(dtos).Send(c)
}

func (h *AdminRetentionHandler) GetRun(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_ID", "Invalid run ID")
	}
	r, err := h.runRepo.GetByID(c.Context(), id)
	if err != nil {
		return response.NotFound(c, "Run not found")
	}
	return response.New().Data(runRecordToDTO(r)).Send(c)
}

// ── Categories ───────────────────────────────────────────────────────

func (h *AdminRetentionHandler) ListCategories(c *fiber.Ctx) error {
	registry := retention.Registry()
	dtos := make([]map[string]interface{}, len(registry))
	for i, m := range registry {
		dtos[i] = map[string]interface{}{
			"category":         m.Category,
			"displayName":      m.DisplayName,
			"description":      m.Description,
			"minRetentionDays": m.MinRetentionDays,
			"protected":        m.Protected,
		}
	}
	return response.New().Data(dtos).Send(c)
}

// ── Helpers ──────────────────────────────────────────────────────────

type PolicyRequest struct {
	Category         string `json:"category"`
	Enabled          bool   `json:"enabled"`
	Strategy         string `json:"strategy"`
	Description      string `json:"description,omitempty"`
	RetentionDays    int    `json:"retentionDays"`
	KeepLatestCount  int    `json:"keepLatestCount"`
	CronExpression   string `json:"cronExpression,omitempty"`
	Timezone         string `json:"timezone"`
	BatchSize        int    `json:"batchSize"`
	MaxBatchesPerRun int    `json:"maxBatchesPerRun"`
	DryRun           bool   `json:"dryRun"`
}

type RunRequest struct {
	Confirm string `json:"confirm"`
}

func policyToDTO(p *retention.PolicyModel) map[string]interface{} {
	dto := map[string]interface{}{
		"id":               p.ID.String(),
		"service":          p.Service,
		"category":         p.Category,
		"enabled":          p.Enabled,
		"strategy":         p.Strategy,
		"description":      p.Description,
		"retentionDays":    p.RetentionDays,
		"keepLatestCount":  p.KeepLatestCount,
		"cronExpression":   p.CronExpression,
		"timezone":         p.Timezone,
		"batchSize":        p.BatchSize,
		"maxBatchesPerRun": p.MaxBatchesPerRun,
		"dryRun":           p.DryRun,
		"minRetentionDays": p.MinRetentionDays,
		"createdAt":        p.CreatedAt.Format(time.RFC3339),
		"updatedAt":        p.UpdatedAt.Format(time.RFC3339),
		"updatedBy":        p.UpdatedBy,
	}
	if p.LastRunAt != nil {
		dto["lastRunAt"] = p.LastRunAt.Format(time.RFC3339)
	}
	if p.NextRunAt != nil {
		dto["nextRunAt"] = p.NextRunAt.Format(time.RFC3339)
	}
	return dto
}

func runRecordToDTO(r *retention.RunRecord) map[string]interface{} {
	dto := map[string]interface{}{
		"id":           r.ID.String(),
		"policyId":     r.PolicyID.String(),
		"service":      r.Service,
		"category":     r.Category,
		"trigger":      r.Trigger,
		"strategy":     r.Strategy,
		"dryRun":       r.DryRun,
		"result":       r.Result,
		"scannedCount": r.ScannedCount,
		"deletedCount": r.DeletedCount,
		"batchesRun":   r.BatchesRun,
		"startedAt":    r.StartedAt.Format(time.RFC3339),
		"createdAt":    r.CreatedAt.Format(time.RFC3339),
	}
	if r.EndedAt != nil {
		dto["endedAt"] = r.EndedAt.Format(time.RFC3339)
		dto["durationMs"] = r.EndedAt.Sub(r.StartedAt).Milliseconds()
	}
	if r.ErrorMsg != "" {
		dto["error"] = r.ErrorMsg
	}
	return dto
}

func getActor(c *fiber.Ctx) string {
	if v := c.Locals("email"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if v := c.Locals("userId"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "system"
}

func (h *AdminRetentionHandler) logAudit(c *fiber.Ctx, action, category string) {
	h.logger.Info(logging.General, logging.Startup, "Retention policy "+action, map[logging.ExtraKey]interface{}{
		"category": category,
		"action":   action,
		"actor":    getActor(c),
	})
}
