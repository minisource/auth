'use client';

/**
 * Admin realtime client — a fetch-based Server-Sent Events stream for admin
 * dashboards (auth service).
 *
 * Native EventSource cannot send an Authorization header, so we read the
 * stream via fetch + ReadableStream and parse SSE frames by hand.
 *
 * Design:
 *  - One connection for all admin events (GET /v1/admin/events).
 *  - Sanitized payloads only (IDs + safe metadata; full records are refetched
 *    through the REST API on invalidation).
 *  - Exponential backoff reconnect (with jitter), heartbeat tolerance
 *    (reconnect if no frame for 2× the server heartbeat), and automatic pause
 *    while the tab is hidden.
 */

export interface AdminRealtimeEvent {
  type: string;
  data?: Record<string, unknown>;
  time: string;
}

export type AdminRealtimeStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'offline';

type EventHandler = (event: AdminRealtimeEvent) => void;
type StatusHandler = (status: AdminRealtimeStatus) => void;

/** Server sends a heartbeat comment every 25s; tolerate ~2.5× that. */
const HEARTBEAT_TIMEOUT_MS = 60_000;
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

class AdminRealtimeClient {
  private url: string | null = null;
  private tokenProvider: (() => string | null) | null = null;

  private controller: AbortController | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setTimeout> | null = null;
  private attempts = 0;
  private stopped = true;
  private connecting = false;

  private handlers = new Map<string, Set<EventHandler>>();
  private statusHandlers = new Set<StatusHandler>();
  private status: AdminRealtimeStatus = 'idle';

  connect(url: string, tokenProvider: () => string | null): void {
    this.url = url;
    this.tokenProvider = tokenProvider;
    this.stopped = false;
    this.attempts = 0;
    this.connectStream();
  }

  disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.clearHeartbeat();
    this.controller?.abort();
    this.controller = null;
    this.setStatus('idle');
  }

  on(type: string, handler: EventHandler): () => void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set());
    }
    this.handlers.get(type)!.add(handler);
    return () => this.handlers.get(type)?.delete(handler);
  }

  onStatus(handler: StatusHandler): () => void {
    this.statusHandlers.add(handler);
    handler(this.status);
    return () => this.statusHandlers.delete(handler);
  }

  getStatus(): AdminRealtimeStatus {
    return this.status;
  }

  private setStatus(status: AdminRealtimeStatus): void {
    if (this.status === status) return;
    this.status = status;
    this.statusHandlers.forEach((h) => h(status));
  }

  private connectStream(): void {
    if (this.stopped || this.connecting || !this.url) return;
    if (typeof document !== 'undefined' && document.hidden) return;

    this.connecting = true;
    const token = this.tokenProvider?.();
    this.controller = new AbortController();
    const signal = this.controller.signal;
    this.setStatus(this.attempts === 0 ? 'connecting' : 'reconnecting');

    fetch(this.url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal,
      cache: 'no-store',
    })
      .then((response) => {
        this.connecting = false;
        // A permanently invalid/expired token should not retry forever.
        if (response.status === 401) {
          this.setStatus('offline');
          return;
        }
        if (!response.ok || !response.body) {
          throw new Error(`SSE error: ${response.status}`);
        }
        this.attempts = 0;
        this.setStatus('connected');
        this.armHeartbeat();
        void this.readStream(response.body);
      })
      .catch((err: unknown) => {
        this.connecting = false;
        if (this.stopped || (err instanceof DOMException && err.name === 'AbortError')) {
          return;
        }
        this.scheduleReconnect();
      });
  }

  private async readStream(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // Split on the SSE frame boundary (blank line).
        let boundary = buffer.indexOf('\n\n');
        while (boundary !== -1) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          this.handleFrame(frame);
          boundary = buffer.indexOf('\n\n');
        }
      }
    } catch {
      // Aborted by disconnect() or a dropped connection — handled below.
    } finally {
      reader.releaseLock();
      this.connecting = false;
    }

    if (!this.stopped) {
      this.scheduleReconnect();
    }
  }

  private handleFrame(frame: string): void {
    this.clearHeartbeat();
    this.armHeartbeat();

    let dataLine = '';
    for (const raw of frame.split('\n')) {
      const line = raw.replace(/\r$/, '');
      if (line.startsWith('data:')) {
        dataLine = line.slice(5).trim();
      }
      // ":" comments (heartbeats) are ignored; "event:"/"id:" are not used.
    }
    if (!dataLine) return;

    try {
      const event = JSON.parse(dataLine) as AdminRealtimeEvent;
      if (!event.type) return;
      const handlers = this.handlers.get(event.type);
      if (handlers) {
        handlers.forEach((h) => h(event));
      }
    } catch {
      // Malformed frame — ignore.
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    this.setStatus('reconnecting');
    const delay = Math.min(
      RECONNECT_BASE_MS * 2 ** this.attempts,
      RECONNECT_MAX_MS,
    ) + Math.random() * 500;
    this.attempts += 1;
    // Clear any pending timer first: scheduleReconnect can be reached from
    // both the fetch catch and the stream's finally, and two timers would
    // open two concurrent SSE connections.
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connectStream();
    }, delay);
  }

  private armHeartbeat(): void {
    this.clearHeartbeat();
    this.heartbeatTimer = setTimeout(() => {
      // No frame for too long — the connection is stale; force a reconnect.
      this.controller?.abort();
      this.scheduleReconnect();
    }, HEARTBEAT_TIMEOUT_MS);
  }

  private clearHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearTimeout(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}

export const adminRealtimeClient = new AdminRealtimeClient();
