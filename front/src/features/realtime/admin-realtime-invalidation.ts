'use client';

import type { QueryClient } from '@tanstack/react-query';
import { QUERY_KEYS } from '@/config/constants';
import type { AdminRealtimeEvent } from './admin-realtime-client';

/**
 * Registry mapping admin SSE event types to the React Query keys they
 * invalidate. The backend pushes only IDs + safe metadata; on each event we
 * invalidate the affected queries so the existing hooks refetch full records
 * through the REST API (redaction stays server-side).
 */

export function handleAdminRealtimeEvent(
  queryClient: QueryClient,
  event: AdminRealtimeEvent,
): void {
  const id = typeof event.data?.id === 'string' ? event.data.id : undefined;
  const userId = typeof event.data?.userId === 'string' ? event.data.userId : undefined;
  const tenantId = typeof event.data?.tenantId === 'string' ? event.data.tenantId : undefined;
  const sessionId = typeof event.data?.sessionId === 'string' ? event.data.sessionId : undefined;

  switch (event.type) {
    case 'login.completed':
    case 'login.failed':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.loginLogs.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.dashboard.recentActivity });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.dashboard.overview });
      if (userId) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.detail(userId) });
      }
      break;

    case 'session.revoked':
    case 'session.expired':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.sessions.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.loginLogs.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.sessions() });
      if (sessionId) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.sessions.detail(sessionId) });
      }
      if (userId) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.detail(userId) });
      }
      break;

    case 'user.created':
    case 'user.updated':
    case 'user.status_changed':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.dashboard.overview });
      if (id) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.detail(id) });
      }
      break;

    case 'role.changed':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.all });
      if (id) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.detail(id) });
      }
      break;

    case 'permission.changed':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.permissions.all });
      break;

    case 'tenant.changed':
    case 'tenant.membership_changed':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.myTenants() });
      if (tenantId) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.detail(tenantId) });
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.members(tenantId) });
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.invitations(tenantId) });
      }
      break;

    case 'settings.changed':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.settings.all });
      break;

    case 'audit.entry_created':
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.auditLogs.all });
      break;

    default:
      break;
  }
}
