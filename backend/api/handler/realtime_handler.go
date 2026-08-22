package handler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/internal/events"
	"github.com/minisource/go-common/logging"
)

// RealtimeHandler streams sanitized admin events over Server-Sent Events.
type RealtimeHandler struct {
	bus       *events.Bus
	logger    logging.Logger
	heartbeat time.Duration
}

// NewRealtimeHandler creates the SSE handler.
func NewRealtimeHandler(bus *events.Bus, logger logging.Logger) *RealtimeHandler {
	return &RealtimeHandler{
		bus:       bus,
		logger:    logger,
		heartbeat: defaultHeartbeatInterval,
	}
}

// defaultHeartbeatInterval keeps proxies and clients from timing out the
// idle connection while no event is flowing. It is a field (not a const) so
// tests can shorten it to verify disconnect handling quickly.
const defaultHeartbeatInterval = 25 * time.Second

// HandleSSE serves GET /v1/admin/events as a text/event-stream.
//
// Auth is enforced by the route group middleware (admin JWT). Each connection
// subscribes to the full event bus (all event types — payloads are sanitized
// at publish time). Frames are written and flushed per event; a heartbeat
// comment is emitted when idle. When the client disconnects, the next flush
// fails and the stream (and its subscription) is torn down.
func (h *RealtimeHandler) HandleSSE(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	ctx := c.Context()
	ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
		ch, unsubscribe := h.bus.Subscribe()
		defer unsubscribe()

		heartbeat := time.NewTicker(h.heartbeat)
		defer heartbeat.Stop()

		// write returns false when the client is gone (flush failure). The
		// stream goroutine must exit then, otherwise the subscription leaks.
		write := func(frame string) bool {
			if _, err := fmt.Fprint(w, frame); err != nil {
				return false
			}
			return w.Flush() == nil
		}

		// Initial comment to establish the stream immediately.
		if !write(": connected\n\n") {
			return
		}

		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return // bus closed
				}
				data, err := json.Marshal(ev)
				if err != nil {
					h.logger.Warn(logging.Internal, logging.Api, "Failed to marshal realtime event", map[logging.ExtraKey]interface{}{
						"error": err.Error(),
						"type":  ev.Type,
					})
					continue
				}
				if !write(fmt.Sprintf("data: %s\n\n", data)) {
					return
				}
			case <-heartbeat.C:
				if !write(": ping\n\n") {
					return
				}
			}
		}
	})

	return nil
}
