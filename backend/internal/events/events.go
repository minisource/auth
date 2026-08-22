// Package events provides a small in-process publish/subscribe bus for
// sanitized admin realtime events, with optional cross-instance fan-out
// through Redis Pub/Sub.
//
// The bus is intentionally minimal: it is a typed fan-out hub used by the
// SSE admin-events endpoint. Services and handlers publish lightweight,
// sanitized payloads (IDs + safe metadata — never passwords, tokens, OTP
// codes, or raw request content). The frontend invalidates React Query keys
// on these events and refetches full records through the existing REST API.
//
// When a Redis client is provided (NewRelayedBus), every published event is
// ALSO forwarded to a shared Redis channel tagged with this instance's ID.
// A subscription goroutine re-publishes events from OTHER instances into the
// local hub, so every connected admin dashboard sees events no matter which
// instance produced them. Events from this instance are skipped to avoid
// echo loops.
package events

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
)

// Event types — keep stable, the frontend registry maps them to query keys.
const (
	TypeLoginCompleted          = "login.completed"
	TypeLoginFailed             = "login.failed"
	TypeSessionRevoked          = "session.revoked"
	TypeSessionExpired          = "session.expired"
	TypeUserCreated             = "user.created"
	TypeUserUpdated             = "user.updated"
	TypeUserStatusChanged       = "user.status_changed"
	TypeRoleChanged             = "role.changed"
	TypePermissionChanged       = "permission.changed"
	TypeTenantChanged           = "tenant.changed"
	TypeTenantMembershipChanged = "tenant.membership_changed"
	TypeSettingsChanged         = "settings.changed"
	TypeAuditEntryCreated       = "audit.entry_created"
)

// Event is a sanitized admin event pushed to connected SSE clients.
type Event struct {
	Type      string    `json:"type"`
	Data      any       `json:"data,omitempty"`
	Timestamp time.Time `json:"time"`
}

// relayEnvelope wraps an event for the Redis channel: the producer instance
// ID lets every instance skip its own echoes.
type relayEnvelope struct {
	InstanceID string `json:"instanceId"`
	Event      Event  `json:"event"`
}

const (
	subscriberBuffer = 128
	redisChannel     = "minisource:auth:admin_events"
)

type subscriber struct {
	ch    chan Event
	types map[string]struct{} // empty = all types
}

// Bus is a non-blocking in-process fan-out hub with optional Redis relay.
type Bus struct {
	mu         sync.RWMutex
	subs       map[*subscriber]struct{}
	logger     logging.Logger
	redis      *redis.Client
	instanceID string
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewBus creates a local-only bus.
func NewBus(logger logging.Logger) *Bus {
	return &Bus{
		subs:   make(map[*subscriber]struct{}),
		logger: logger,
	}
}

// NewRelayedBus creates a bus that also fans events out to other instances
// through Redis Pub/Sub. The subscription goroutine runs until Close.
// A nil rdb is safe — it degrades to a local-only bus.
func NewRelayedBus(logger logging.Logger, rdb *redis.Client) *Bus {
	b := NewBus(logger)
	if rdb == nil {
		return b
	}
	b.redis = rdb
	b.instanceID = uuid.NewString()

	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel

	b.wg.Add(1)
	go b.redisRelayLoop(ctx)

	return b
}

// redisRelayLoop subscribes to the shared channel and re-publishes events
// produced by OTHER instances into the local hub.
func (b *Bus) redisRelayLoop(ctx context.Context) {
	defer b.wg.Done()

	pubsub := b.redis.Subscribe(ctx, redisChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				// Unexpected pubsub closure (e.g. Redis dropped) — make the
				// degradation observable instead of failing silently.
				b.logger.Warn(logging.Redis, logging.Api, "Realtime event relay pubsub closed unexpectedly", nil)
				return
			}
			var env relayEnvelope
			if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
				continue
			}
			if env.InstanceID == b.instanceID {
				continue // own echo — already delivered locally
			}
			if env.Event.Type == "" {
				continue
			}
			b.publishLocal(env.Event)
		}
	}
}

// Subscribe registers a subscriber for the given event types. An empty
// types list subscribes to all events. Returns a receive-only channel and an
// unsubscribe function that must be called when the subscriber is done.
func (b *Bus) Subscribe(types ...string) (<-chan Event, func()) {
	s := &subscriber{
		ch:    make(chan Event, subscriberBuffer),
		types: make(map[string]struct{}, len(types)),
	}
	for _, t := range types {
		s.types[t] = struct{}{}
	}

	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()

	return s.ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
		b.mu.Unlock()
	}
}

// Publish broadcasts an event to all matching subscribers without blocking
// the caller, and (when relaying) forwards it to other instances.
func (b *Bus) Publish(typ string, data any) {
	ev := Event{
		Type:      typ,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}
	b.publishLocal(ev)

	if b.redis != nil && b.instanceID != "" {
		env := relayEnvelope{InstanceID: b.instanceID, Event: ev}
		payload, err := json.Marshal(env)
		if err != nil {
			return
		}
		// Best-effort: a failed relay must never block the local hot path.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = b.redis.Publish(ctx, redisChannel, payload).Err()
		cancel()
		if err != nil {
			b.logger.Warn(logging.Redis, logging.Api, "Realtime event relay failed", map[logging.ExtraKey]interface{}{
				logging.ExtraKey("type"):  typ,
				logging.ExtraKey("error"): err.Error(),
			})
		}
	}
}

// publishLocal delivers an event to all matching local subscribers without
// blocking. Subscribers whose buffer is full are dropped (slow consumer).
func (b *Bus) publishLocal(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if len(s.types) > 0 {
			if _, ok := s.types[ev.Type]; !ok {
				continue
			}
		}
		select {
		case s.ch <- ev:
		default:
			b.logger.Warn(logging.Internal, logging.Api, "Realtime subscriber buffer full, dropping event", map[logging.ExtraKey]interface{}{
				logging.ExtraKey("type"): ev.Type,
			})
		}
	}
}

// Close terminates every subscriber (closing their channels) so blocked SSE
// handlers exit promptly, and stops the Redis relay goroutine. Safe to call
// multiple times.
func (b *Bus) Close() {
	b.mu.Lock()
	for s := range b.subs {
		delete(b.subs, s)
		close(s.ch)
	}
	b.mu.Unlock()

	if b.cancel != nil {
		b.cancel()
	}
	b.wg.Wait()
}

// Len returns the number of active subscribers (mainly for tests).
func (b *Bus) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
