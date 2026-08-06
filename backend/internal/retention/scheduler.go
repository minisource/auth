package retention

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/retention"
)

// Scheduler periodically runs enabled retention policies.
// It uses a simple ticker loop (same pattern as Notifier's BalanceScheduler).
type Scheduler struct {
	policyRepo PolicyRepository
	runRepo    RunRepository
	runner     *AuthRunner
	lock       *PGLock
	logger     logging.Logger
	stop       chan struct{}
	mu         sync.Mutex
	running    bool
}

func NewScheduler(
	policyRepo PolicyRepository,
	runRepo RunRepository,
	runner *AuthRunner,
	lock *PGLock,
	logger logging.Logger,
) *Scheduler {
	return &Scheduler{
		policyRepo: policyRepo,
		runRepo:    runRepo,
		runner:     runner,
		lock:       lock,
		logger:     logger,
		stop:       make(chan struct{}),
	}
}

// Start begins the scheduler loop. Safe to call multiple times.
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.logger.Info(logging.General, logging.Startup, "Retention scheduler started", nil)
	go s.loop()
}

// Stop signals the scheduler to shut down.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stop)
	s.running = false
}

func (s *Scheduler) loop() {
	// Tick every minute to check for due policies
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Run once immediately on startup
	s.tick()

	for {
		select {
		case <-ticker.C:
			s.tick()
		case <-s.stop:
			s.logger.Info(logging.General, logging.Startup, "Retention scheduler stopped", nil)
			return
		}
	}
}

func (s *Scheduler) tick() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	policies, err := s.policyRepo.ListEnabled(ctx)
	if err != nil {
		s.logger.Error(logging.General, logging.Startup, "Failed to list enabled retention policies", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return
	}

	for _, pm := range policies {
		s.executePolicy(ctx, pm)
	}
}

func (s *Scheduler) executePolicy(ctx context.Context, pm PolicyModel) {
	policy := pm.ToDomain()

	// Validate the policy
	if err := ValidatePolicy(&policy); err != nil {
		s.logger.Warn(logging.General, logging.Startup, "Skipping invalid policy", map[logging.ExtraKey]interface{}{
			"category": policy.Category,
			"error":    err.Error(),
		})
		return
	}

	// Acquire distributed lock
	lockKeyStr := LockKey(policy.Service, policy.Category)
	guard, err := s.lock.Acquire(ctx, lockKeyStr, 10*time.Minute)
	if err != nil {
		if err == retention.ErrLockHeld {
			s.logger.Debug(logging.General, logging.Startup, "Cleanup lock held by another instance", map[logging.ExtraKey]interface{}{
				"category": policy.Category,
			})
			retention.CleanupLockContentionTotal.WithLabelValues(policy.Service, policy.Category).Inc()
		} else {
			s.logger.Error(logging.General, logging.Startup, "Failed to acquire cleanup lock", map[logging.ExtraKey]interface{}{
				"category": policy.Category,
				"error":    err.Error(),
			})
		}
		return
	}
	defer guard.Release(ctx)

	// Build snapshot with age cutoff
	cutoff := policy.ComputeCutoff(time.Now().UTC())

	// For count/hybrid strategies, combine with count cutoff (AND semantics)
	if policy.Strategy == retention.StrategyCount || policy.Strategy == retention.StrategyHybrid {
		if countCutoff, err := s.runner.ComputeCountCutoff(ctx, policy.Category, policy.KeepLatestCount); err == nil && !countCutoff.IsZero() {
			if policy.Strategy == retention.StrategyCount || countCutoff.Before(cutoff) {
				cutoff = countCutoff
			}
		}
	}

	snapshot := retention.RunSnapshot{
		PolicyID:   policy.ID,
		Service:    policy.Service,
		Category:   policy.Category,
		Strategy:   policy.Strategy,
		DryRun:     policy.DryRun,
		Cutoff:     cutoff,
		KeepLatest: policy.KeepLatestCount,
		BatchSize:  policy.EffectiveBatchSize(),
		MaxBatches: policy.EffectiveMaxBatches(),
		Trigger:    retention.TriggerScheduled,
		RunID:      uuid.New().String(),
		StartedAt:  time.Now().UTC(),
	}

	// Execute
	retention.CleanupActive.WithLabelValues(policy.Service, policy.Category).Set(1)
	defer retention.CleanupActive.WithLabelValues(policy.Service, policy.Category).Set(0)

	runner, err := s.runner.NewSharedRunner(snapshot)
	if err != nil {
		s.logger.Error(logging.General, logging.Startup, "Failed to create runner", map[logging.ExtraKey]interface{}{
			"category": policy.Category,
			"error":    err.Error(),
		})
		return
	}

	result := runner.Run(ctx)

	// Record result
	record, err := RecordRun(ctx, s.runRepo, snapshot, result)
	if err != nil {
		s.logger.Error(logging.General, logging.Startup, "Failed to record run", map[logging.ExtraKey]interface{}{
			"category": policy.Category,
			"error":    err.Error(),
		})
	}

	// Metrics
	retention.CleanupRunsTotal.WithLabelValues(policy.Service, policy.Category, string(result.Result), string(snapshot.Trigger)).Inc()
	retention.CleanupDeletedRecordsTotal.WithLabelValues(policy.Service, policy.Category).Add(float64(result.DeletedCount))
	dur := result.EndedAt.Sub(result.StartedAt).Seconds()
	retention.CleanupDurationSeconds.WithLabelValues(policy.Service, policy.Category, string(result.Result)).Observe(dur)

	if result.Result == retention.ResultSuccess || result.Result == retention.ResultPartial {
		retention.CleanupLastSuccessTimestamp.WithLabelValues(policy.Service, policy.Category).Set(float64(result.EndedAt.Unix()))
	}
	if result.Result == retention.ResultFailed {
		reason := "unknown"
		if result.Error != nil {
			reason = result.Error.Error()
			if len(reason) > 50 {
				reason = reason[:50]
			}
		}
		retention.CleanupFailuresTotal.WithLabelValues(policy.Service, policy.Category, reason).Inc()
	}

	// Update policy last run time
	now := time.Now().UTC()
	pm.LastRunAt = &now
	if record != nil {
		pm.NextRunAt = computeNextRun(policy.CronExpression)
	}
	_ = s.policyRepo.Update(ctx, &pm)

	s.logger.Info(logging.General, logging.Startup, "Retention run completed", map[logging.ExtraKey]interface{}{
		"category":      policy.Category,
		"result":        string(result.Result),
		"deleted_count": result.DeletedCount,
		"batches":       result.BatchesRun,
		"duration_ms":   dur * 1000,
	})
}

// ExecuteManual runs a cleanup policy immediately (manual trigger).
// It returns the RunRecord for audit.
func (s *Scheduler) ExecuteManual(ctx context.Context, pm PolicyModel) (*RunRecord, error) {
	policy := pm.ToDomain()

	if err := ValidatePolicy(&policy); err != nil {
		return nil, err
	}

	lockKeyStr := LockKey(policy.Service, policy.Category)
	guard, err := s.lock.Acquire(ctx, lockKeyStr, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	defer guard.Release(ctx)

	cutoff := policy.ComputeCutoff(time.Now().UTC())
	if policy.Strategy == retention.StrategyCount || policy.Strategy == retention.StrategyHybrid {
		if countCutoff, err := s.runner.ComputeCountCutoff(ctx, policy.Category, policy.KeepLatestCount); err == nil && !countCutoff.IsZero() {
			if policy.Strategy == retention.StrategyCount || countCutoff.Before(cutoff) {
				cutoff = countCutoff
			}
		}
	}

	snapshot := retention.RunSnapshot{
		PolicyID:   policy.ID,
		Service:    policy.Service,
		Category:   policy.Category,
		Strategy:   policy.Strategy,
		DryRun:     policy.DryRun,
		Cutoff:     cutoff,
		KeepLatest: policy.KeepLatestCount,
		BatchSize:  policy.EffectiveBatchSize(),
		MaxBatches: policy.EffectiveMaxBatches(),
		Trigger:    retention.TriggerManual,
		RunID:      uuid.New().String(),
		StartedAt:  time.Now().UTC(),
	}

	retention.CleanupActive.WithLabelValues(policy.Service, policy.Category).Set(1)
	defer retention.CleanupActive.WithLabelValues(policy.Service, policy.Category).Set(0)

	runner, err := s.runner.NewSharedRunner(snapshot)
	if err != nil {
		return nil, err
	}

	result := runner.Run(ctx)
	record, err := RecordRun(ctx, s.runRepo, snapshot, result)
	if err != nil {
		return record, err
	}

	// Metrics
	retention.CleanupRunsTotal.WithLabelValues(policy.Service, policy.Category, string(result.Result), string(snapshot.Trigger)).Inc()
	retention.CleanupDeletedRecordsTotal.WithLabelValues(policy.Service, policy.Category).Add(float64(result.DeletedCount))
	dur := result.EndedAt.Sub(result.StartedAt).Seconds()
	retention.CleanupDurationSeconds.WithLabelValues(policy.Service, policy.Category, string(result.Result)).Observe(dur)

	// Update last run
	now := time.Now().UTC()
	pm.LastRunAt = &now
	_ = s.policyRepo.Update(ctx, &pm)

	return record, nil
}

// GetRunner returns the underlying AuthRunner (used by handlers for preview).
func (s *Scheduler) GetRunner() *AuthRunner { return s.runner }

func computeNextRun(cronExpr string) *time.Time {
	if cronExpr == "" {
		return nil
	}
	// Use the shared validation package to compute next run
	loc, _ := time.LoadLocation("UTC")
	next := retention.NextRun(cronExpr, loc)
	if next.IsZero() {
		return nil
	}
	return &next
}
