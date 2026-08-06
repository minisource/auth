/**
 * Cache time constants for React Query
 */
export const CACHE_TIME = {
  /** 30 seconds */
  INSTANT: 30 * 1000,
  /** 1 minute */
  SHORT: 1 * 60 * 1000,
  /** 5 minutes */
  MEDIUM: 5 * 60 * 1000,
  /** 30 minutes */
  LONG: 30 * 60 * 1000,
  /** 1 hour */
  VERY_LONG: 60 * 60 * 1000,
  /** 24 hours */
  DAY: 24 * 60 * 60 * 1000,
} as const;

/**
 * Query keys for React Query
 * Centralized management of query keys for better cache invalidation
 */
export const QUERY_KEYS = {
  // Auth related
  auth: {
    all: ['auth'] as const,
    profile: () => ['auth', 'profile'] as const,
    sessions: () => ['auth', 'sessions'] as const,
    linkedAccounts: () => ['auth', 'linked-accounts'] as const,
    myTenants: () => ['auth', 'my-tenants'] as const,
  },
  // Admin related
  admin: {
    all: ['admin'] as const,
    users: {
      all: ['admin', 'users'] as const,
      list: (params?: Record<string, unknown>) => ['admin', 'users', 'list', params] as const,
      detail: (id: string) => ['admin', 'users', id] as const,
    },
    roles: {
      all: ['admin', 'roles'] as const,
      detail: (id: string) => ['admin', 'roles', id] as const,
    },
    permissions: {
      all: ['admin', 'permissions'] as const,
      list: (resource?: string) => ['admin', 'permissions', 'list', resource] as const,
      detail: (id: string) => ['admin', 'permissions', id] as const,
    },
    serviceClients: {
      all: ['admin', 'service-clients'] as const,
      detail: (id: string) => ['admin', 'service-clients', id] as const,
    },
    tenants: {
      all: ['admin', 'tenants'] as const,
      list: (page?: number) => ['admin', 'tenants', 'list', page] as const,
      detail: (id: string) => ['admin', 'tenants', id] as const,
      members: (id: string) => ['admin', 'tenants', id, 'members'] as const,
      invitations: (id: string) => ['admin', 'tenants', id, 'invitations'] as const,
    },
    settings: {
      all: ['admin', 'settings'] as const,
      category: (cat: string) => ['admin', 'settings', cat] as const,
    },
    dashboard: {
      overview: ['admin', 'dashboard', 'overview'] as const,
      recentActivity: ['admin', 'dashboard', 'recent-activity'] as const,
    },
    loginLogs: {
      all: ['admin', 'login-logs'] as const,
      list: (action?: string) => ['admin', 'login-logs', action] as const,
    },
    sessions: {
      all: ['admin', 'sessions'] as const,
      list: (page?: number) => ['admin', 'sessions', 'list', page] as const,
      detail: (id: string) => ['admin', 'sessions', id] as const,
    },
    oauthProviders: {
      all: ['admin', 'oauth-providers'] as const,
      list: (page?: number) => ['admin', 'oauth-providers', 'list', page] as const,
      detail: (id: string) => ['admin', 'oauth-providers', id] as const,
    },
    auditLogs: {
      all: ['admin', 'audit-logs'] as const,
      list: (page?: number) => ['admin', 'audit-logs', 'list', page] as const,
    },
    tools: {
      jwksStatus: ['admin', 'tools', 'jwks-status'] as const,
      health: ['admin', 'tools', 'health'] as const,
    },
  },
} as const;
