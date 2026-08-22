package events

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/minisource/go-common/audit"
)

// errAuditLoggerNotConfigured is returned when the wrapped audit logger is
// nil (defensive — the real wiring always provides one).
var errAuditLoggerNotConfigured = errors.New("audit logger not configured")

// PublishingAuditLogger wraps an audit.Logger and publishes a sanitized
// audit.entry_created event after every successful write, so the admin audit
// feed updates in realtime. Only IDs, action, and entity type are published —
// never values/changes maps (they can contain sensitive content).
type PublishingAuditLogger struct {
	inner audit.Logger
	bus   *Bus
}

// NewPublishingAuditLogger wraps inner with realtime event publishing.
// A nil inner is safe (writes fail with an error, nothing is published).
func NewPublishingAuditLogger(inner audit.Logger, bus *Bus) audit.Logger {
	return &PublishingAuditLogger{inner: inner, bus: bus}
}

// publish emits the sanitized audit event after a successful persist.
func (p *PublishingAuditLogger) publish(entry *audit.AuditLog) {
	if p.bus == nil || entry == nil {
		return
	}
	p.bus.Publish(TypeAuditEntryCreated, map[string]any{
		"id":         entry.ID,
		"tenantId":   entry.TenantID,
		"userId":     entry.UserID,
		"action":     entry.Action,
		"entityType": entry.EntityType,
		"entityId":   entry.EntityID,
	})
}

// Log persists an audit entry and publishes an event on success.
func (p *PublishingAuditLogger) Log(ctx context.Context, entry *audit.AuditLog) error {
	if p.inner == nil {
		return errAuditLoggerNotConfigured
	}
	if err := p.inner.Log(ctx, entry); err != nil {
		return err
	}
	p.publish(entry)
	return nil
}

// LogAction persists a structured audit entry and publishes an event on
// success. The changes map is intentionally never forwarded to the bus.
func (p *PublishingAuditLogger) LogAction(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	action, entityType string,
	entityID *uuid.UUID,
	changes map[string]interface{},
) error {
	if p.inner == nil {
		return errAuditLoggerNotConfigured
	}
	if err := p.inner.LogAction(ctx, tenantID, userID, action, entityType, entityID, changes); err != nil {
		return err
	}
	p.publish(&audit.AuditLog{
		ID:         uuid.New(),
		TenantID:   tenantID,
		UserID:     &userID,
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
	})
	return nil
}

// Query delegates to the inner logger.
func (p *PublishingAuditLogger) Query(ctx context.Context, filter *audit.Filter) ([]*audit.AuditLog, error) {
	if p.inner == nil {
		return nil, errAuditLoggerNotConfigured
	}
	return p.inner.Query(ctx, filter)
}
