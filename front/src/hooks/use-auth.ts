/**
 * Authentication hooks
 * React Query hooks for all auth operations
 */
'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from '@minisource/ui';
import { useRouter } from 'next/navigation';
import { authApi, userApi, adminApi, accountApi } from '@/api';
import { useAuthStore } from '@/stores';
import { QUERY_KEYS, CACHE_TIME } from '@/config/constants';
import { isAppError, type AppError } from '@/shared/errors/app-error';
import type {
  LoginRequest,
  RegisterRequest,
  SendOTPRequest,
  VerifyOTPRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  UpdateProfileRequest,
  ChangePasswordRequest,
  SetPasswordRequest,
  ListUsersParams,
  CreateUserRequest,
  UpdateUserRequest,
  CreateRoleRequest,
  UpdateRoleRequest,
  CreatePermissionRequest,
  UpdatePermissionRequest,
  CreateServiceClientRequest,
} from '@/types/auth';
import type {
  CreateTenantRequest,
  UpdateSettingsRequest,
  CreateOAuthProviderRequest,
  UpdateOAuthProviderRequest,
} from '@/types/admin';

/**
 * Extracts the best user-facing error message from a mutation error.
 * Prefers AppError.userMessage (safe, localized) over raw .message.
 */
function getErrorMessage(error: unknown, fallback: string): string {
  if (isAppError(error)) {
    return (error as AppError).userMessage || (error as AppError).message || fallback;
  }
  if (typeof error === 'object' && error !== null && 'message' in error) {
    return (error as { message: string }).message || fallback;
  }
  return fallback;
}

/**
 * Path prefixes served by OTHER MiniSource frontends behind the gateway.
 * Navigating to these from the auth app must be a FULL page load so the target
 * app boots its own router state — client-side router.replace would send an RSC
 * request with the auth app's router state tree to the other app's URL, which
 * the other app cannot parse ("router state header could not be parsed" / 500).
 */
const CROSS_APP_PATH_PREFIXES = [
  '/notifier/',
  '/log/',
  '/scheduler/',
  '/storage/',
  '/comment/',
  '/ticket/',
  '/feedback/',
];

function isCrossAppPath(path: string): boolean {
  // Match both the bare prefix (e.g. "/notifier") and any sub-path under it
  // (e.g. "/notifier/dashboard") so a returnUrl without a trailing slash
  // does not fall back to client-side navigation across apps.
  return CROSS_APP_PATH_PREFIXES.some((prefix) => {
    const bare = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    return path === bare || path.startsWith(prefix);
  });
}

/**
 * Resolves the post-auth redirect target from ?returnUrl and navigates to it.
 * Same-app targets use client-side navigation; cross-app targets (other
 * MiniSource frontends) trigger a full page load to avoid RSC state mismatch.
 */
function navigateAfterAuth(router: ReturnType<typeof useRouter>, fallback: string) {
  const searchParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const returnUrl = searchParams?.get('returnUrl');
  const target = returnUrl && returnUrl.startsWith('/') && !returnUrl.startsWith('//') ? returnUrl : fallback;

  if (typeof window !== 'undefined' && isCrossAppPath(target)) {
    window.location.assign(target);
    return;
  }
  router.replace(target);
}

// ==================== Auth Hooks ====================

/**
 * Hook to get current user profile
 */
export function useCurrentUser() {
  const { isAuthenticated, updateUser } = useAuthStore();

  return useQuery({
    queryKey: QUERY_KEYS.auth.profile(),
    queryFn: async () => {
      const profile = await userApi.getProfile();
      if (profile) {
        updateUser(profile);
      }
      return profile;
    },
    enabled: isAuthenticated,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook for login mutation
 */
export function useLogin() {
  const queryClient = useQueryClient();
  const { setAuth } = useAuthStore();
  const router = useRouter();

  return useMutation({
    mutationFn: ({ rememberMe: _rememberMe, ...credentials }: LoginRequest & { rememberMe?: boolean }) =>
      authApi.login(credentials),
    onSuccess: (data, vars) => {
      const rm = (vars as { rememberMe?: boolean }).rememberMe;
      setAuth(data.user, { accessToken: data.accessToken, refreshToken: data.refreshToken }, rm);
      toast.success('Login successful!');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.all });

      navigateAfterAuth(router, '/dashboard');
    },
    onError: (error: unknown) => {
      toast.error(getErrorMessage(error, 'Login failed'));
    },
  });
}

/**
 * Hook for register mutation
 */
export function useRegister() {
  const router = useRouter();

  return useMutation({
    mutationFn: (data: RegisterRequest) => authApi.register(data),
    onSuccess: () => {
      toast.success('Registration successful! Please check your email to verify your account.');
      router.push('/login');
    },
    onError: (error: unknown) => {
      toast.error(getErrorMessage(error, 'Registration failed'));
    },
  });
}

/**
 * Hook for OTP login - send OTP
 */
export function useSendOTP() {
  return useMutation({
    mutationFn: (data: SendOTPRequest) => authApi.sendOTP(data),
    onSuccess: (data) => {
      toast.success(data.message || 'OTP sent successfully');
    },
    onError: (error: unknown) => {
      toast.error(getErrorMessage(error, 'Failed to send OTP'));
    },
  });
}

/**
 * Hook for OTP login - verify OTP
 */
export function useVerifyOTP() {
  const queryClient = useQueryClient();
  const { setAuth } = useAuthStore();
  const router = useRouter();

  return useMutation({
    mutationFn: ({ rememberMe: _rememberMe, ...data }: VerifyOTPRequest & { rememberMe?: boolean }) =>
      authApi.verifyOTP(data),
    onSuccess: (data, vars) => {
      const rm = (vars as { rememberMe?: boolean }).rememberMe;
      setAuth(data.user, { accessToken: data.accessToken, refreshToken: data.refreshToken }, rm);
      toast.success('Login successful!');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.all });

      navigateAfterAuth(router, '/dashboard');
    },
    onError: (error: unknown) => {
      toast.error(getErrorMessage(error, 'OTP verification failed'));
    },
  });
}

/**
 * Hook for logout
 */
export function useLogout() {
  const queryClient = useQueryClient();
  const { clearAuth } = useAuthStore();
  const router = useRouter();

  return useMutation({
    mutationFn: () => authApi.logout(),
    onSettled: () => {
      clearAuth();
      queryClient.clear();
      toast.success('Logged out successfully');
      router.replace('/login');
    },
  });
}

/**
 * Hook for forgot password
 */
export function useForgotPassword() {
  return useMutation({
    mutationFn: (data: ForgotPasswordRequest) => authApi.forgotPassword(data),
    onSuccess: (data) => {
      toast.success(data.message || 'Password reset OTP sent');
    },
    onError: (error: unknown) => {
      toast.error(getErrorMessage(error, 'Failed to send password reset'));
    },
  });
}

/**
 * Hook for reset password
 */
export function useResetPassword() {
  const router = useRouter();

  return useMutation({
    mutationFn: (data: ResetPasswordRequest) => authApi.resetPassword(data),
    onSuccess: () => {
      toast.success('Password reset successfully. Please login with your new password.');
      router.push('/login');
    },
    onError: (error: unknown) => {
      toast.error(getErrorMessage(error, 'Failed to reset password'));
    },
  });
}

// ==================== Profile Hooks ====================

/**
 * Hook to update profile
 */
export function useUpdateProfile() {
  const { updateUser } = useAuthStore();

  return useMutation({
    mutationFn: (data: UpdateProfileRequest) => userApi.updateProfile(data),
    onSuccess: (data) => {
      updateUser(data);
      toast.success('Profile updated successfully');
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update profile');
    },
  });
}

/**
 * Hook to change password
 */
export function useChangePassword() {
  return useMutation({
    mutationFn: (data: ChangePasswordRequest) => userApi.changePassword(data),
    onSuccess: () => {
      toast.success('Password changed successfully');
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to change password');
    },
  });
}

/**
 * Hook to set password (for OTP users)
 */
export function useSetPassword() {
  return useMutation({
    mutationFn: (data: SetPasswordRequest) => userApi.setPassword(data),
    onSuccess: () => {
      toast.success('Password set successfully');
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to set password');
    },
  });
}

/**
 * Hook to get user sessions
 */
export function useUserSessions() {
  const { isAuthenticated } = useAuthStore();

  return useQuery({
    queryKey: QUERY_KEYS.auth.sessions(),
    queryFn: () => userApi.getSessions(),
    enabled: isAuthenticated,
    staleTime: CACHE_TIME.SHORT,
  });
}

/**
 * Hook to get linked accounts
 */
export function useLinkedAccounts() {
  const { isAuthenticated } = useAuthStore();

  return useQuery({
    queryKey: QUERY_KEYS.auth.linkedAccounts(),
    queryFn: () => userApi.getLinkedAccounts(),
    enabled: isAuthenticated,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to unlink Google account
 */
export function useUnlinkGoogle() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => userApi.unlinkGoogle(),
    onSuccess: () => {
      toast.success('Google account unlinked');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.linkedAccounts() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to unlink Google account');
    },
  });
}

// ==================== Admin User Hooks ====================

/**
 * Hook to list users (admin)
 */
export function useAdminUsers(params?: ListUsersParams) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.users.list(params as Record<string, unknown>),
    queryFn: () => adminApi.listUsers(params),
    staleTime: CACHE_TIME.SHORT,
  });
}

/**
 * Hook to get user by ID (admin)
 */
export function useAdminUser(id: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.users.detail(id),
    queryFn: () => adminApi.getUser(id),
    enabled: !!id,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to create user (admin)
 */
export function useCreateUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateUserRequest) => adminApi.createUser(data),
    onSuccess: () => {
      toast.success('User created successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to create user');
    },
  });
}

/**
 * Hook to update user (admin)
 */
export function useUpdateUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateUserRequest }) =>
      adminApi.updateUser(id, data),
    onSuccess: () => {
      toast.success('User updated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update user');
    },
  });
}

/**
 * Hook to delete user (admin)
 */
export function useDeleteUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.deleteUser(id),
    onSuccess: () => {
      toast.success('User deleted successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to delete user');
    },
  });
}

/**
 * Hook to toggle user status
 */
export function useToggleUserStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'active' | 'inactive' }) =>
      adminApi.toggleUserStatus(id, status),
    onSuccess: () => {
      toast.success('User status updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update user status');
    },
  });
}

/**
 * Hook to unlock user
 */
export function useUnlockUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.unlockUser(id),
    onSuccess: () => {
      toast.success('User unlocked successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.users.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to unlock user');
    },
  });
}

// ==================== Admin Role Hooks ====================

/**
 * Hook to list roles
 */
export function useRoles() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.roles.all,
    queryFn: () => adminApi.listRoles(),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get role by ID
 */
export function useRole(id: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.roles.detail(id),
    queryFn: () => adminApi.getRole(id),
    enabled: !!id,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to create role
 */
export function useCreateRole() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateRoleRequest) => adminApi.createRole(data),
    onSuccess: () => {
      toast.success('Role created successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to create role');
    },
  });
}

/**
 * Hook to update role
 */
export function useUpdateRole() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateRoleRequest }) =>
      adminApi.updateRole(id, data),
    onSuccess: () => {
      toast.success('Role updated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update role');
    },
  });
}

/**
 * Hook to delete role
 */
export function useDeleteRole() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.deleteRole(id),
    onSuccess: () => {
      toast.success('Role deleted successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to delete role');
    },
  });
}

/**
 * Hook to assign permission to role
 */
export function useAssignPermissionToRole() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ roleId, permissionId }: { roleId: string; permissionId: string }) =>
      adminApi.assignPermissionToRole(roleId, permissionId),
    onSuccess: () => {
      toast.success('Permission assigned to role');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to assign permission');
    },
  });
}

/**
 * Hook to remove permission from role
 */
export function useRemovePermissionFromRole() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ roleId, permissionId }: { roleId: string; permissionId: string }) =>
      adminApi.removePermissionFromRole(roleId, permissionId),
    onSuccess: () => {
      toast.success('Permission removed from role');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.roles.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to remove permission');
    },
  });
}

// ==================== Admin Permission Hooks ====================

/**
 * Hook to list permissions
 */
export function usePermissions(resource?: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.permissions.list(resource),
    queryFn: () => adminApi.listPermissions(resource),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to create permission
 */
export function useCreatePermission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreatePermissionRequest) => adminApi.createPermission(data),
    onSuccess: () => {
      toast.success('Permission created successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.permissions.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to create permission');
    },
  });
}

/**
 * Hook to update permission
 */
export function useUpdatePermission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdatePermissionRequest }) =>
      adminApi.updatePermission(id, data),
    onSuccess: () => {
      toast.success('Permission updated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.permissions.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update permission');
    },
  });
}

/**
 * Hook to delete permission
 */
export function useDeletePermission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.deletePermission(id),
    onSuccess: () => {
      toast.success('Permission deleted successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.permissions.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to delete permission');
    },
  });
}

// ==================== Service Client Hooks ====================

// ==================== Service Client Hooks ====================

/**
 * Hook to list service clients
 */
export function useServiceClients() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.serviceClients.all,
    queryFn: () => adminApi.listServiceClients(),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get service client by ID
 */
export function useServiceClient(id: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.serviceClients.detail(id),
    queryFn: () => adminApi.getServiceClient(id),
    enabled: !!id,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to create service client
 */
export function useCreateServiceClient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateServiceClientRequest) => adminApi.createServiceClient(data),
    onSuccess: () => {
      toast.success('Service client created successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.serviceClients.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to create service client');
    },
  });
}

/**
 * Hook to update service client
 */
export function useUpdateServiceClient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: CreateServiceClientRequest }) =>
      adminApi.updateServiceClient(id, data),
    onSuccess: () => {
      toast.success('Service client updated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.serviceClients.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update service client');
    },
  });
}

/**
 * Hook to delete service client
 */
export function useDeleteServiceClient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.deleteServiceClient(id),
    onSuccess: () => {
      toast.success('Service client deleted successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.serviceClients.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to delete service client');
    },
  });
}

/**
 * Hook to rotate service client secret
 */
export function useRotateServiceClientSecret() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.rotateServiceClientSecret(id),
    onSuccess: () => {
      toast.success('Client secret rotated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.serviceClients.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to rotate client secret');
    },
  });
}

/**
 * Hook to toggle service client status
 */
export function useToggleServiceClientStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'active' | 'inactive' }) =>
      adminApi.toggleServiceClientStatus(id, status),
    onSuccess: () => {
      toast.success('Service client status updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.serviceClients.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update service client status');
    },
  });
}

// ==================== Admin Dashboard Hooks ====================

/**
 * Hook to get dashboard overview
 */
export function useAdminDashboard() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.dashboard.overview,
    queryFn: () => adminApi.getDashboardOverview(),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get recent activity
 */
export function useRecentActivity() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.dashboard.recentActivity,
    queryFn: () => adminApi.getRecentActivity(),
    staleTime: CACHE_TIME.SHORT,
    retry: false,
  });
}

/**
 * Hook to get system health status
 */
export function useSystemHealth() {
  const { isAuthenticated } = useAuthStore();
  return useQuery({
    queryKey: ['admin', 'tools', 'health'],
    queryFn: () => adminApi.toolsHealth(),
    enabled: isAuthenticated,
    staleTime: CACHE_TIME.SHORT,
    retry: false,
  });
}

/**
 * Hook to get recent login logs for security overview
 */
export function useRecentLoginLogs(limit = 5) {
  const { isAuthenticated } = useAuthStore();
  return useQuery({
    queryKey: ['admin', 'login-logs', 'recent', limit],
    queryFn: () => adminApi.listLoginLogs({ limit }),
    enabled: isAuthenticated,
    staleTime: CACHE_TIME.SHORT,
    retry: false,
  });
}

/**
 * Hook to get active sessions
 */
export function useActiveSessions(limit = 5) {
  const { isAuthenticated } = useAuthStore();
  return useQuery({
    queryKey: ['admin', 'sessions', 'active', limit],
    queryFn: async () => {
      const res = await adminApi.listAllSessions({ limit, isActive: true });
      return res?.data || [];
    },
    enabled: isAuthenticated,
    staleTime: CACHE_TIME.SHORT,
    retry: false,
  });
}

// ==================== Admin Tenant Hooks ====================

/**
 * Hook to list tenants
 */
export function useAdminTenants(page = 1) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.tenants.list(page),
    queryFn: () => adminApi.listTenants(page),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get tenant by ID
 */
export function useAdminTenant(id: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.tenants.detail(id),
    queryFn: () => adminApi.getTenant(id),
    enabled: !!id,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to create tenant
 */
export function useCreateTenant() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateTenantRequest) => adminApi.createTenant(data),
    onSuccess: () => {
      toast.success('Tenant created successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
      // The creator is auto-added as owner, so refresh the tenant selector list too
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.myTenants() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to create tenant');
    },
  });
}

/**
 * Hook to update tenant
 */
export function useUpdateTenant() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateTenantRequest> }) =>
      adminApi.updateTenant(id, data),
    onSuccess: () => {
      toast.success('Tenant updated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.myTenants() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update tenant');
    },
  });
}

/**
 * Hook to delete tenant
 */
export function useDeleteTenant() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.deleteTenant(id),
    onSuccess: () => {
      toast.success('Tenant deleted successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.myTenants() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to delete tenant');
    },
  });
}

/**
 * Hook to toggle tenant status
 */
export function useToggleTenantStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'active' | 'inactive' | 'suspended' }) =>
      adminApi.toggleTenantStatus(id, status),
    onSuccess: () => {
      toast.success('Tenant status updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.myTenants() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update tenant status');
    },
  });
}

/**
 * Hook to list tenant members
 */
export function useTenantMembers(tenantId: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.tenants.members(tenantId),
    queryFn: () => adminApi.listTenantMembers(tenantId),
    enabled: !!tenantId,
    staleTime: CACHE_TIME.SHORT,
  });
}

/**
 * Hook to remove tenant member
 */
export function useRemoveTenantMember() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ tenantId, userId }: { tenantId: string; userId: string }) =>
      adminApi.removeTenantMember(tenantId, userId),
    onSuccess: () => {
      toast.success('Member removed from tenant');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to remove member');
    },
  });
}

// ==================== Admin Settings Hooks ====================

/**
 * Hook to get all settings
 */
export function useAdminSettings() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.settings.all,
    queryFn: () => adminApi.getSettings(),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get settings by category
 */
export function useAdminSettingsByCategory(category: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.settings.category(category),
    queryFn: () => adminApi.getSettingsByCategory(category),
    enabled: !!category,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to update settings
 */
export function useUpdateAdminSettings() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: UpdateSettingsRequest) => adminApi.updateSettings(data),
    onSuccess: () => {
      toast.success('Settings updated successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.settings.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update settings');
    },
  });
}

// ==================== Admin OAuth Provider Hooks ====================

/**
 * Hook to list OAuth providers
 */
export function useAdminOAuthProviders(params: { page?: number; pageSize?: number; tenantId?: string } = {}) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.oauthProviders.list(params.page ?? 1),
    queryFn: () => adminApi.listOAuthProviders(params),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get single OAuth provider
 */
export function useAdminOAuthProvider(id: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.oauthProviders.detail(id),
    queryFn: () => adminApi.getOAuthProvider(id),
    enabled: !!id,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to create OAuth provider
 */
export function useCreateOAuthProvider() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateOAuthProviderRequest) => adminApi.createOAuthProvider(data),
    onSuccess: () => {
      toast.success('OAuth provider created');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.oauthProviders.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to create provider');
    },
  });
}

/**
 * Hook to update OAuth provider
 */
export function useUpdateOAuthProvider() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateOAuthProviderRequest }) =>
      adminApi.updateOAuthProvider(id, data),
    onSuccess: () => {
      toast.success('OAuth provider updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.oauthProviders.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update provider');
    },
  });
}

/**
 * Hook to delete OAuth provider
 */
export function useDeleteOAuthProvider() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.deleteOAuthProvider(id),
    onSuccess: () => {
      toast.success('OAuth provider deleted');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.oauthProviders.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to delete provider');
    },
  });
}

/**
 * Hook to toggle OAuth provider
 */
export function useToggleOAuthProvider() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.toggleOAuthProvider(id),
    onSuccess: () => {
      toast.success('Provider status updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.oauthProviders.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to toggle provider');
    },
  });
}

// ==================== Admin Login Log Hooks ====================

/**
 * Hook to list login logs
 */
export function useLoginLogs(params: { action?: string; search?: string; orderBy?: string; sort?: 'asc' | 'desc'; limit?: number } = {}) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.loginLogs.list(params.action),
    queryFn: () => adminApi.listLoginLogs(params),
    staleTime: CACHE_TIME.SHORT,
  });
}

/**
 * Hook to introspect a token
 */
export function useIntrospectToken() {
  return useMutation({
    mutationFn: (token: string) => adminApi.introspectToken(token),
  });
}

// ==================== Admin Session Hooks ====================

/**
 * Hook to list all sessions (admin)
 */
export function useAdminSessions(params: { page?: number; limit?: number; search?: string; isActive?: boolean; orderBy?: string; sort?: 'asc' | 'desc' } = {}) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.sessions.list(params.page ?? 1),
    queryFn: () => adminApi.listAllSessions({ page: params.page ?? 1, limit: params.limit ?? 20, search: params.search, isActive: params.isActive, orderBy: params.orderBy, sort: params.sort }),
    staleTime: CACHE_TIME.SHORT,
  });
}

/**
 * Hook to revoke a session (admin)
 */
export function useAdminRevokeSession() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => adminApi.revokeSession(id),
    onSuccess: () => {
      toast.success('Session revoked successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.sessions.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to revoke session');
    },
  });
}

/**
 * Hook to revoke all sessions for a user (admin)
 */
export function useAdminRevokeUserAllSessions() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (userId: string) => adminApi.revokeUserAllSessions(userId),
    onSuccess: () => {
      toast.success('All sessions revoked for user');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.sessions.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to revoke user sessions');
    },
  });
}

// ==================== Permission Detail Hook ====================

/**
 * Hook to get permission by ID
 */
export function usePermission(id: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.permissions.detail(id),
    queryFn: () => adminApi.getPermission(id),
    enabled: !!id,
    staleTime: CACHE_TIME.MEDIUM,
  });
}

// ==================== Tenant Member Management Hooks ====================

/**
 * Hook to add tenant member
 */
export function useAddTenantMember() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ tenantId, data }: { tenantId: string; data: { userId: string; roleId?: string } }) =>
      adminApi.addTenantMember(tenantId, data),
    onSuccess: () => {
      toast.success('Member added to tenant');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to add member');
    },
  });
}

/**
 * Hook to update tenant member role
 */
export function useUpdateTenantMember() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ tenantId, userId, data }: { tenantId: string; userId: string; data: { roleId?: string } }) =>
      adminApi.updateTenantMember(tenantId, userId, data),
    onSuccess: () => {
      toast.success('Member role updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update member');
    },
  });
}

// ==================== Tenant Invitation Hooks ====================

/**
 * Hook to list tenant invitations
 */
export function useTenantInvitations(tenantId: string) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.tenants.invitations(tenantId),
    queryFn: () => adminApi.listTenantInvitations(tenantId),
    enabled: !!tenantId,
    staleTime: CACHE_TIME.SHORT,
  });
}

/**
 * Hook to invite tenant member
 */
export function useInviteTenantMember() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ tenantId, data }: { tenantId: string; data: { email: string; roleId?: string } }) =>
      adminApi.inviteTenantMember(tenantId, data),
    onSuccess: () => {
      toast.success('Invitation sent');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to send invitation');
    },
  });
}

/**
 * Hook to revoke tenant invitation
 */
export function useRevokeTenantInvitation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ tenantId, invitationId }: { tenantId: string; invitationId: string }) =>
      adminApi.revokeTenantInvitation(tenantId, invitationId),
    onSuccess: () => {
      toast.success('Invitation revoked');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.tenants.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to revoke invitation');
    },
  });
}

// ==================== Settings Hooks ====================

/**
 * Hook to update settings by category
 */
export function useUpdateAdminSettingsByCategory() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ category, data }: { category: string; data: UpdateSettingsRequest }) =>
      adminApi.updateSettingsByCategory(category, data),
    onSuccess: () => {
      toast.success('Settings updated');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.admin.settings.all });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to update settings');
    },
  });
}

// ==================== Audit Logs Hooks ====================

/**
 * Hook to list audit logs
 */
export function useAuditLogs(params: { page?: number; limit?: number; action?: string; userId?: string; tenantId?: string } = {}) {
  return useQuery({
    queryKey: QUERY_KEYS.admin.auditLogs.list(params.page ?? 1),
    queryFn: () => adminApi.listAuditLogs(params),
    staleTime: CACHE_TIME.SHORT,
  });
}

// ==================== Google Mobile Login Hook ====================

/**
 * Hook for Google mobile login
 */
export function useGoogleMobileLogin() {
  const queryClient = useQueryClient();
  const { setAuth } = useAuthStore();
  const router = useRouter();

  return useMutation({
    mutationFn: (data: { idToken: string }) => authApi.googleMobileLogin(data),
    onSuccess: (data) => {
      setAuth(data.user, { accessToken: data.accessToken, refreshToken: data.refreshToken });
      toast.success('Login successful!');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.all });
      router.push('/dashboard');
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Google login failed');
    },
  });
}

// ==================== Phone Verification Hooks ====================

/**
 * Hook to start phone verification
 */
export function usePhoneStart() {
  return useMutation({
    mutationFn: (phone: string) => accountApi.phoneStart({ phone }),
    onSuccess: (data) => {
      toast.success(data.message || 'Verification code sent to phone');
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to send verification code');
    },
  });
}

/**
 * Hook to verify phone with OTP
 */
export function usePhoneVerify() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: { phone: string; code: string }) => accountApi.phoneVerify(data),
    onSuccess: () => {
      toast.success('Phone verified successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.profile() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Phone verification failed');
    },
  });
}

// ==================== Email Verification Hooks ====================

/**
 * Hook to verify email with OTP
 */
export function useVerifyEmail() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: { target: string; code: string }) =>
      authApi.verifyEmail({ target: data.target, code: data.code, type: 'email_verification' }),
    onSuccess: () => {
      toast.success('Email verified successfully');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.auth.profile() });
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Email verification failed');
    },
  });
}

/**
 * Hook to resend verification code
 */
export function useResendVerification() {
  return useMutation({
    mutationFn: (data: { email?: string; phone?: string }) => authApi.resendVerification(data),
    onSuccess: (data) => {
      toast.success(data.message || 'Verification code resent');
    },
    onError: (error: { message?: string }) => {
      toast.error(error.message || 'Failed to resend verification code');
    },
  });
}

// ==================== Admin Tools Hooks ====================

/**
 * Hook to check if a user has a specific permission
 */
export function useCheckPermission() {
  return useMutation({
    mutationFn: (data: { userId?: string; permission: string; tenantId?: string }) =>
      adminApi.checkPermission(data),
  });
}

/**
 * Hook to get JWKS status
 */
export function useJwksStatus() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.tools.jwksStatus,
    queryFn: () => adminApi.jwksStatus(),
    staleTime: CACHE_TIME.MEDIUM,
  });
}

/**
 * Hook to get tools health
 */
export function useToolsHealth() {
  return useQuery({
    queryKey: QUERY_KEYS.admin.tools.health,
    queryFn: () => adminApi.toolsHealth(),
    staleTime: CACHE_TIME.MEDIUM,
  });
}
