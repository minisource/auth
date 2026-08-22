'use client';

import { useEffect, useState } from 'react';
import { useT } from '@/shared/i18n/LanguageProvider';
import { useAuthStore } from '@/stores';
import { adminRealtimeClient, type AdminRealtimeStatus } from './admin-realtime-client';
import { useAdminRealtime } from './use-admin-realtime';

const STATUS_DOT: Record<AdminRealtimeStatus, string> = {
  idle: 'bg-muted-foreground/40',
  connecting: 'bg-amber-500 animate-pulse',
  connected: 'bg-emerald-500',
  reconnecting: 'bg-amber-500 animate-pulse',
  offline: 'bg-red-500',
};

const STATUS_TITLE: Record<AdminRealtimeStatus, string> = {
  idle: 'realtime.status.idle',
  connecting: 'realtime.status.connecting',
  connected: 'realtime.status.connected',
  reconnecting: 'realtime.status.reconnecting',
  offline: 'realtime.status.offline',
};

/**
 * Small live-connection dot rendered in the topbar. It also mounts the admin
 * realtime subscription while an authenticated admin is present.
 */
export function RealtimeStatusIndicator() {
  const { t } = useT();
  useAdminRealtime();

  const [status, setStatus] = useState<AdminRealtimeStatus>(() =>
    adminRealtimeClient.getStatus(),
  );

  useEffect(() => {
    return adminRealtimeClient.onStatus(setStatus);
  }, []);

  // Subscribe to the store so the indicator (and the underlying SSE hook)
  // reacts to auth changes instead of reading a one-time snapshot.
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  if (!isAuthenticated) return null;

  return (
    <span
      title={t(STATUS_TITLE[status])}
      className="inline-flex items-center gap-1.5 rounded-full border border-border/60 px-2 py-0.5 text-[10px] font-medium text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      <span
        className={`h-2 w-2 rounded-full transition-colors ${STATUS_DOT[status]}`}
        aria-hidden="true"
      />
      {t(`realtime.status.${status === 'connected' ? 'live' : 'sync'}`)}
    </span>
  );
}
