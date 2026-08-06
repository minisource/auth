import { api } from '../client';
import { BaseApi } from '../base';
import type {
  AdminUser,
  CreateUserRequest,
  UpdateUserRequest,
  ListUsersParams,
  PaginatedUsersResponse,
  Role,
  CreateRoleRequest,
  UpdateRoleRequest,
  Permission,
  CreatePermissionRequest,
  UpdatePermissionRequest,
  ServiceClient,
  CreateServiceClientRequest,
  MessageResponse,
} from '@/types/auth';
import type {
  Tenant,
  CreateTenantRequest,
  TenantMember,
  AddTenantMemberRequest,
  TenantInvitation,
  InviteTenantMemberRequest,
  Setting,
  SettingsGroup,
  UpdateSettingsRequest,
  DashboardOverview,
  RecentActivity,
  LoginLog,
  AdminSession,
  ListSessionsParams,
  OAuthProvider,
  CreateOAuthProviderRequest,
  UpdateOAuthProviderRequest,
  IntrospectResponse,
} from '@/types/admin';

/**
 * Admin API service - user, role, permission, and service client management
 */
class AdminApi extends BaseApi {
  constructor() {
    super('/admin');
  }

  // ==================== User Management ====================

  /**
   * List all users
   * GET /api/v1/admin/users
   */
  async listUsers(params?: ListUsersParams): Promise<PaginatedUsersResponse> {
    return api.get<PaginatedUsersResponse>(
      this.url('/users'),
      params as Record<string, unknown>
    );
  }

  /**
   * Get user by ID
   * GET /api/v1/admin/users/:id
   */
  async getUser(id: string): Promise<AdminUser> {
    return api.get<AdminUser>(this.url(`/users/${id}`));
  }

  /**
   * Create user
   * POST /api/v1/admin/users
   */
  async createUser(data: CreateUserRequest): Promise<AdminUser> {
    return api.post<AdminUser>(this.url('/users'), data);
  }

  /**
   * Update user
   * PUT /api/v1/admin/users/:id
   */
  async updateUser(id: string, data: UpdateUserRequest): Promise<AdminUser> {
    return api.put<AdminUser>(this.url(`/users/${id}`), data);
  }

  /**
   * Delete user
   * DELETE /api/v1/admin/users/:id
   */
  async deleteUser(id: string): Promise<void> {
    return api.delete(this.url(`/users/${id}`));
  }

  /**
   * Toggle user status
   * PATCH /api/v1/admin/users/:id/status/:status
   */
  async toggleUserStatus(id: string, status: 'active' | 'inactive'): Promise<AdminUser> {
    return api.patch<AdminUser>(this.url(`/users/${id}/status/${status}`));
  }

  /**
   * Unlock user
   * POST /api/v1/admin/users/:id/unlock
   */
  async unlockUser(id: string): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url(`/users/${id}/unlock`));
  }

  // ==================== Role Management ====================

  /**
   * List all roles
   * GET /api/v1/admin/roles
   */
  async listRoles(): Promise<Role[]> {
    return api.get<Role[]>(this.url('/roles'));
  }

  /**
   * Get role by ID
   * GET /api/v1/admin/roles/:id
   */
  async getRole(id: string): Promise<Role> {
    return api.get<Role>(this.url(`/roles/${id}`));
  }

  /**
   * Create role
   * POST /api/v1/admin/roles
   */
  async createRole(data: CreateRoleRequest): Promise<Role> {
    return api.post<Role>(this.url('/roles'), data);
  }

  /**
   * Update role
   * PUT /api/v1/admin/roles/:id
   */
  async updateRole(id: string, data: UpdateRoleRequest): Promise<Role> {
    return api.put<Role>(this.url(`/roles/${id}`), data);
  }

  /**
   * Delete role
   * DELETE /api/v1/admin/roles/:id
   */
  async deleteRole(id: string): Promise<void> {
    return api.delete(this.url(`/roles/${id}`));
  }

  /**
   * Assign permission to role
   * POST /api/v1/admin/roles/:roleId/permissions/:permissionId
   */
  async assignPermissionToRole(roleId: string, permissionId: string): Promise<MessageResponse> {
    return api.post<MessageResponse>(
      this.url(`/roles/${roleId}/permissions/${permissionId}`)
    );
  }

  /**
   * Remove permission from role
   * DELETE /api/v1/admin/roles/:roleId/permissions/:permissionId
   */
  async removePermissionFromRole(roleId: string, permissionId: string): Promise<MessageResponse> {
    return api.delete<MessageResponse>(
      this.url(`/roles/${roleId}/permissions/${permissionId}`)
    );
  }

  // ==================== Permission Management ====================

  /**
   * List all permissions
   * GET /api/v1/admin/permissions
   */
  async listPermissions(resource?: string): Promise<Permission[]> {
    const params = resource ? { resource } : undefined;
    return api.get<Permission[]>(
      this.url('/permissions'),
      params as Record<string, unknown>
    );
  }

  /**
   * Get permission by ID
   * GET /api/v1/admin/permissions/:id
   */
  async getPermission(id: string): Promise<Permission> {
    return api.get<Permission>(this.url(`/permissions/${id}`));
  }

  /**
   * Create permission
   * POST /api/v1/admin/permissions
   */
  async createPermission(data: CreatePermissionRequest): Promise<Permission> {
    return api.post<Permission>(this.url('/permissions'), data);
  }

  /**
   * Update permission
   * PUT /api/v1/admin/permissions/:id
   */
  async updatePermission(id: string, data: UpdatePermissionRequest): Promise<Permission> {
    return api.put<Permission>(this.url(`/permissions/${id}`), data);
  }

  /**
   * Delete permission
   * DELETE /api/v1/admin/permissions/:id
   */
  async deletePermission(id: string): Promise<void> {
    return api.delete(this.url(`/permissions/${id}`));
  }

  // ==================== Service Client Management ====================

  /**
   * List all service clients
   * GET /api/v1/admin/service-clients
   */
  async listServiceClients(): Promise<ServiceClient[]> {
    return api.get<ServiceClient[]>(this.url('/service-clients'));
  }

  /**
   * Get service client by ID
   * GET /api/v1/admin/service-clients/:id
   */
  async getServiceClient(id: string): Promise<ServiceClient> {
    return api.get<ServiceClient>(this.url(`/service-clients/${id}`));
  }

  /**
   * Create service client
   * POST /api/v1/admin/service-clients
   */
  async createServiceClient(data: CreateServiceClientRequest): Promise<ServiceClient> {
    return api.post<ServiceClient>(this.url('/service-clients'), data);
  }

  /**
   * Update service client
   * PUT /api/v1/admin/service-clients/:id
   */
  async updateServiceClient(id: string, data: CreateServiceClientRequest): Promise<ServiceClient> {
    return api.put<ServiceClient>(this.url(`/service-clients/${id}`), data);
  }

  /**
   * Delete service client
   * DELETE /api/v1/admin/service-clients/:id
   */
  async deleteServiceClient(id: string): Promise<void> {
    return api.delete(this.url(`/service-clients/${id}`));
  }

  /**
   * Toggle service client status
   * PATCH /api/v1/admin/service-clients/:id/status
   */
  async toggleServiceClientStatus(id: string, status: 'active' | 'inactive'): Promise<ServiceClient> {
    return api.patch<ServiceClient>(this.url(`/service-clients/${id}/status/${status}`));
  }

  /**
   * Rotate service client secret
   * POST /api/v1/admin/service-clients/:id/rotate-secret
   */
  async rotateServiceClientSecret(id: string): Promise<ServiceClient> {
    return api.post<ServiceClient>(this.url(`/service-clients/${id}/rotate-secret`));
  }

  // ==================== Tenant Management ====================

  /**
   * List all tenants
   * GET /api/v1/admin/tenants
   */
  async listTenants(page = 1, pageSize = 20): Promise<{ data: Tenant[]; meta: { page: number; pageSize: number; total: number; totalPages: number } }> {
    return api.get(this.url('/tenants'), { page, pageSize } as Record<string, unknown>);
  }

  /**
   * Get tenant by ID
   * GET /api/v1/admin/tenants/:id
   */
  async getTenant(id: string): Promise<Tenant> {
    return api.get<Tenant>(this.url(`/tenants/${id}`));
  }

  /**
   * Create tenant
   * POST /api/v1/admin/tenants
   */
  async createTenant(data: CreateTenantRequest): Promise<Tenant> {
    return api.post<Tenant>(this.url('/tenants'), data);
  }

  /**
   * Update tenant
   * PUT /api/v1/admin/tenants/:id
   */
  async updateTenant(id: string, data: Partial<CreateTenantRequest>): Promise<Tenant> {
    return api.put<Tenant>(this.url(`/tenants/${id}`), data);
  }

  /**
   * Delete tenant
   * DELETE /api/v1/admin/tenants/:id
   */
  async deleteTenant(id: string): Promise<void> {
    return api.delete(this.url(`/tenants/${id}`));
  }

  /**
   * Toggle tenant status
   * PATCH /api/v1/admin/tenants/:id/status/:status
   */
  async toggleTenantStatus(id: string, status: 'active' | 'inactive' | 'suspended'): Promise<void> {
    return api.patch(this.url(`/tenants/${id}/status/${status}`));
  }

  /**
   * List tenant members
   * GET /api/v1/admin/tenants/:id/members
   */
  async listTenantMembers(tenantId: string): Promise<TenantMember[]> {
    return api.get<TenantMember[]>(this.url(`/tenants/${tenantId}/members`));
  }

  /**
   * Add member to tenant
   * POST /api/v1/admin/tenants/:id/members
   */
  async addTenantMember(tenantId: string, data: AddTenantMemberRequest): Promise<void> {
    return api.post(this.url(`/tenants/${tenantId}/members`), data);
  }

  /**
   * Update tenant member role
   * PATCH /api/v1/admin/tenants/:id/members/:userId
   */
  async updateTenantMember(tenantId: string, userId: string, data: { roleId?: string }): Promise<TenantMember> {
    return api.patch<TenantMember>(this.url(`/tenants/${tenantId}/members/${userId}`), data);
  }

  /**
   * Remove member from tenant
   * DELETE /api/v1/admin/tenants/:id/members/:userId
   */
  async removeTenantMember(tenantId: string, userId: string): Promise<void> {
    return api.delete(this.url(`/tenants/${tenantId}/members/${userId}`));
  }

  /**
   * List tenant invitations
   * GET /api/v1/admin/tenants/:id/invitations
   */
  async listTenantInvitations(tenantId: string): Promise<TenantInvitation[]> {
    return api.get<TenantInvitation[]>(this.url(`/tenants/${tenantId}/invitations`));
  }

  /**
   * Invite member to tenant
   * POST /api/v1/admin/tenants/:id/invitations
   */
  async inviteTenantMember(tenantId: string, data: InviteTenantMemberRequest): Promise<TenantInvitation> {
    return api.post<TenantInvitation>(this.url(`/tenants/${tenantId}/invitations`), data);
  }

  /**
   * Revoke tenant invitation
   * DELETE /api/v1/admin/tenants/:id/invitations/:invitationId
   */
  async revokeTenantInvitation(tenantId: string, invitationId: string): Promise<void> {
    return api.delete(this.url(`/tenants/${tenantId}/invitations/${invitationId}`));
  }

  // ==================== Settings Management ====================

  /**
   * Get all settings (grouped by category)
   * GET /api/v1/admin/settings
   */
  async getSettings(): Promise<SettingsGroup> {
    return api.get<SettingsGroup>(this.url('/settings'));
  }

  /**
   * Get settings by category
   * GET /api/v1/admin/settings/:category
   */
  async getSettingsByCategory(category: string): Promise<Setting[]> {
    return api.get<Setting[]>(this.url(`/settings/${category}`));
  }

  /**
   * Update settings
   * PATCH /api/v1/admin/settings
   */
  async updateSettings(data: UpdateSettingsRequest): Promise<MessageResponse> {
    return api.patch<MessageResponse>(this.url('/settings'), data);
  }

  /**
   * Update settings by category
   * PATCH /api/v1/admin/settings/:category
   */
  async updateSettingsByCategory(category: string, data: UpdateSettingsRequest): Promise<MessageResponse> {
    return api.patch<MessageResponse>(this.url(`/settings/${category}`), data);
  }

  // ==================== Dashboard ====================

  /**
   * Get dashboard overview
   * GET /api/v1/admin/dashboard/overview
   */
  async getDashboardOverview(): Promise<DashboardOverview> {
    return api.get<DashboardOverview>(this.url('/dashboard/overview'));
  }

  /**
   * Get recent activity
   * GET /api/v1/admin/dashboard/recent-activity
   */
  async getRecentActivity(): Promise<RecentActivity[]> {
    return api.get<RecentActivity[]>(this.url('/dashboard/recent-activity'));
  }

  // ==================== Sessions Management ====================

  /**
   * List all sessions
   * GET /api/v1/admin/sessions
   */
  async listAllSessions(params: ListSessionsParams = {}): Promise<{ data: AdminSession[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
    const query: Record<string, unknown> = {};
    if (params.page) query.page = params.page;
    if (params.limit) query.limit = params.limit;
    if (params.search) query.search = params.search;
    if (params.userId) query.userId = params.userId;
    if (params.isActive !== undefined) query.isActive = params.isActive;
    if (params.orderBy) query.orderBy = params.orderBy;
    if (params.sort) query.sort = params.sort;
    return api.get(this.url('/sessions'), query);
  }

  /**
   * Revoke a session
   * DELETE /api/v1/admin/sessions/:id
   */
  async revokeSession(id: string): Promise<MessageResponse> {
    return api.delete<MessageResponse>(this.url(`/sessions/${id}`));
  }

  /**
   * Revoke all sessions for a user
   * DELETE /api/v1/admin/users/:userId/sessions
   */
  async revokeUserAllSessions(userId: string): Promise<MessageResponse> {
    return api.delete<MessageResponse>(this.url(`/users/${userId}/sessions`));
  }

  // ==================== Login Logs ====================

  /**
   * List login logs
   * GET /api/v1/admin/login-logs
   */
  async listLoginLogs(params: { action?: string; search?: string; orderBy?: string; sort?: 'asc' | 'desc'; limit?: number } = {}): Promise<LoginLog[]> {
    const query: Record<string, unknown> = {};
    if (params.action) query.action = params.action;
    if (params.search) query.search = params.search;
    if (params.orderBy) query.orderBy = params.orderBy;
    if (params.sort) query.sort = params.sort;
    if (params.limit) query.limit = params.limit;
    return api.get<LoginLog[]>(this.url('/login-logs'), query);
  }

  // ==================== OAuth Providers ====================

  /**
   * List OAuth providers
   * GET /api/v1/admin/oauth-providers
   */
  async listOAuthProviders(params: { page?: number; pageSize?: number; tenantId?: string } = {}): Promise<{ data: OAuthProvider[]; meta: { page: number; pageSize: number; total: number; totalPages: number } }> {
    const query: Record<string, unknown> = {};
    if (params.page) query.page = params.page;
    if (params.pageSize) query.pageSize = params.pageSize;
    if (params.tenantId) query.tenantId = params.tenantId;
    return api.get(this.url('/oauth-providers'), query);
  }

  /**
   * Get OAuth provider by ID
   * GET /api/v1/admin/oauth-providers/:id
   */
  async getOAuthProvider(id: string): Promise<OAuthProvider> {
    return api.get<OAuthProvider>(this.url(`/oauth-providers/${id}`));
  }

  /**
   * Create OAuth provider
   * POST /api/v1/admin/oauth-providers
   */
  async createOAuthProvider(data: CreateOAuthProviderRequest): Promise<OAuthProvider> {
    return api.post<OAuthProvider>(this.url('/oauth-providers'), data);
  }

  /**
   * Update OAuth provider
   * PUT /api/v1/admin/oauth-providers/:id
   */
  async updateOAuthProvider(id: string, data: UpdateOAuthProviderRequest): Promise<OAuthProvider> {
    return api.put<OAuthProvider>(this.url(`/oauth-providers/${id}`), data);
  }

  /**
   * Delete OAuth provider
   * DELETE /api/v1/admin/oauth-providers/:id
   */
  async deleteOAuthProvider(id: string): Promise<void> {
    return api.delete(this.url(`/oauth-providers/${id}`));
  }

  /**
   * Toggle OAuth provider enabled/disabled
   * PATCH /api/v1/admin/oauth-providers/:id/toggle
   */
  async toggleOAuthProvider(id: string): Promise<{ id: string; isEnabled: boolean }> {
    return api.patch(this.url(`/oauth-providers/${id}/toggle`));
  }

  // ==================== Tools ====================

  /**
   * Introspect token
   * POST /api/v1/admin/tools/introspect-token
   */
  async introspectToken(token: string): Promise<IntrospectResponse> {
    return api.post<IntrospectResponse>(this.url('/tools/introspect-token'), { token });
  }

  /**
   * Check permission
   * POST /api/v1/admin/tools/check-permission
   */
  async checkPermission(data: { userId?: string; permission: string; tenantId?: string }): Promise<{ hasPermission: boolean }> {
    return api.post<{ hasPermission: boolean }>(this.url('/tools/check-permission'), data);
  }

  /**
   * JWKS status
   * GET /api/v1/admin/tools/jwks-status
   */
  async jwksStatus(): Promise<{ keys: number; algorithm: string; lastRotated: string }> {
    return api.get(this.url('/tools/jwks-status'));
  }

  /**
   * Tools health
   * GET /api/v1/admin/tools/health
   */
  async toolsHealth(): Promise<{ db: string; redis: string; version: string }> {
    return api.get(this.url('/tools/health'));
  }

  // ==================== Audit Logs ====================

  /**
   * List audit logs
   * GET /api/v1/admin/audit-logs
   */
  async listAuditLogs(params: { page?: number; limit?: number; action?: string; userId?: string; tenantId?: string; orderBy?: string; sort?: 'asc' | 'desc' } = {}): Promise<{ data: Record<string, unknown>[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
    const query: Record<string, unknown> = {};
    if (params.page) query.page = params.page;
    if (params.limit) query.limit = params.limit;
    if (params.action) query.action = params.action;
    if (params.userId) query.userId = params.userId;
    if (params.tenantId) query.tenantId = params.tenantId;
    if (params.orderBy) query.orderBy = params.orderBy;
    if (params.sort) query.sort = params.sort;
    return api.get(this.url('/audit-logs'), query);
  }
}

export const adminApi = new AdminApi();
