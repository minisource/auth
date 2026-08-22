'use client';

import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { config } from '@/config';
import { useAuthStore } from '@/stores';
import { adminRealtimeClient, type AdminRealtimeEvent } from './admin-realtime-client';
import { handleAdminRealtimeEvent } from './admin-realtime-invalidation';

const EVENT_TYPES = [
  'login.completed',
  'login.failed',
  'session.revoked',
  'session.expired',
  'user.created',
  'user.updated',
  'user.status_changed',
  'role.changed',
  'permission.changed',
  'tenant.changed',
  'tenant.membership_changed',
  'settings.changed',
  'audit.entry_created',
];

/** Same token resolution as the axios client (store first, storage fallback). */
function getAccessToken(): string | null {
  const storeToken = useAuthStore.getState().tokens?.accessToken;
  if (storeToken) return storeToken;
  if (typeof window === 'undefined') return null;
  return (
    window.localStorage.getItem('accessToken') ||
    window.sessionStorage.getItem('accessToken')
  );
}

/**
 * Connects the admin SSE stream while an authenticated admin is present and
 * routes every event through the query-key invalidation registry. Existing
 * hooks keep working as a polling fallback when the stream is down.
 *
 * The endpoint requires an admin role, so non-admin users never connect
 * (avoids a 403 retry loop). Reconnects on visibility change (the client
 * pauses while hidden).
 */
export function useAdminRealtime(): void {
  const queryClient = useQueryClient();
  const urlRef = useRef<string | null>(null);
  // Subscribe to auth state so the connection starts/stops with login state.
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isAdmin = useAuthStore((s) => s.user?.roles?.includes('admin') || s.user?.roles?.includes('super_admin'));

  useEffect(() => {
    if (!isAuthenticated) return;
    if (!isAdmin) return;

    const url = `${config.api.baseUrl}/admin/events`;
    urlRef.current = url;

    const unsubscribes = EVENT_TYPES.map((type) =>
      adminRealtimeClient.on(type, (event: AdminRealtimeEvent) => {
        handleAdminRealtimeEvent(queryClient, event);
      }),
    );

    adminRealtimeClient.connect(url, () => getAccessToken());

    const handleVisibility = () => {
      if (document.hidden) {
        // Pause the stream while the tab is hidden; polling fallbacks keep
        // the data fresh, and we reconnect when the tab is visible again.
        adminRealtimeClient.disconnect();
      } else if (urlRef.current) {
        adminRealtimeClient.connect(urlRef.current, () => getAccessToken());
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibility);
      unsubscribes.forEach((unsub) => unsub());
      adminRealtimeClient.disconnect();
    };
  }, [queryClient, isAuthenticated, isAdmin]);
}
