/**
 * Admin-specific types for tenant, settings, dashboard, sessions, audit
 */

// === Tenant Types ===

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  displayName?: string;
  description?: string;
  logo?: string;
  domain?: string;
  status: 'active' | 'inactive' | 'suspended' | 'trial';
  isDefault: boolean;
  plan: string;
  contactEmail?: string;
  createdAt: string;
  updatedAt: string;
}

export interface TenantMember {
  tenantId: string;
  userId: string;
  roleId?: string;
  isOwner: boolean;
  isDefault: boolean;
  joinedAt: string;
  user?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    username: string;
  };
  role?: {
    id: string;
    name: string;
  };
}

export interface TenantInvitation {
  id: string;
  tenantId: string;
  email: string;
  roleId?: string;
  expiresAt: string;
  createdAt: string;
}

export interface CreateTenantRequest {
  name: string;
  slug: string;
  displayName?: string;
  description?: string;
  domain?: string;
  contactEmail?: string;
}

export interface UpdateTenantRequest {
  name?: string;
  displayName?: string;
  description?: string;
  domain?: string;
  status?: string;
}

export interface AddTenantMemberRequest {
  userId: string;
  roleId?: string;
}

export interface InviteTenantMemberRequest {
  email: string;
  role?: string;
}

// === Settings Types ===

export interface Setting {
  key: string;
  value: string;
  type: string;
  category: string;
  description?: string;
  isPublic: boolean;
}

export interface SettingsGroup {
  [key: string]: Setting[];
}

export interface UpdateSettingsRequest {
  [key: string]: string;
}

// === Dashboard Types ===

export interface DashboardOverview {
  users: {
    total: number;
    active: number;
    locked: number;
    unverifiedEmail: number;
    newToday: number;
    newLast7Days: number;
  };
  accessControl: {
    roles: number;
    permissions: number;
  };
  tenants: {
    total: number;
  };
  integrations: {
    serviceClients: number;
    oauthProviders?: number;
  };
  security: {
    activeSessions: number;
    failedLogins24h: number;
  };
}

export interface RecentActivity {
  id: string;
  userId: string;
  action: string;
  success: boolean;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  userEmail?: string;
  userName?: string;
}

// === Session Types ===

export interface AdminSession {
  id: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceType?: string;
  isActive: boolean;
  expiresAt: string;
  lastActiveAt: string;
  revokedAt?: string;
  createdAt: string;
  updatedAt: string;
  userEmail: string;
  userFirstName: string;
  userLastName: string;
}

export interface ListSessionsParams {
  page?: number;
  limit?: number;
  search?: string;
  userId?: string;
  isActive?: boolean;
  orderBy?: string;
  sort?: 'asc' | 'desc';
}

// === Login Log Types ===

export interface LoginLog {
  id: string;
  userId: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  errorMsg?: string;
  createdAt: string;
  userEmail?: string;
  userName?: string;
}

// === Tool Response Types ===

export interface IntrospectResponse {
  active: boolean;
  sub?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  scopes?: string[];
  exp?: number;
  tokenType?: string;
  sessionId?: string;
  error?: string;
}

export interface PermissionCheckResponse {
  exists: boolean;
  roleName?: string;
  hasPermission: boolean;
  message?: string;
}

// === OAuth Provider Types ===

export interface OAuthProvider {
  id: string;
  tenantId?: string;
  name: string;
  type: string;
  clientId: string;
  clientSecret: string;
  redirectUrl?: string;
  scopes?: string;
  authUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
  isEnabled: boolean;
  isDefault: boolean;
  config: Record<string, unknown>;
  totalLogins: number;
  successfulLogins: number;
  failedLogins: number;
  lastUsedAt?: string;
  createdAt: string;
  updatedAt: string;
  tenant?: { id: string; name: string; slug: string };
}

export interface CreateOAuthProviderRequest {
  name: string;
  type: string;
  clientId: string;
  clientSecret: string;
  redirectUrl?: string;
  scopes?: string;
  authUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
  tenantId?: string;
  config?: Record<string, unknown>;
}

export interface UpdateOAuthProviderRequest {
  name?: string;
  clientId?: string;
  clientSecret?: string;
  redirectUrl?: string;
  scopes?: string;
  authUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
  config?: Record<string, unknown>;
}
