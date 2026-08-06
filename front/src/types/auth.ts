/**
 * Authentication and User types matching the auth backend DTOs
 */

// === Auth DTOs ===

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
}

export interface SendOTPRequest {
  phone?: string;
  email?: string;
  type?: 'login' | 'email_verification' | 'phone_verification' | 'password_reset';
  firstName?: string;
  lastName?: string;
}

export interface VerifyOTPRequest {
  target: string; // Phone or Email
  code: string;
  type: 'login' | 'email_verification' | 'phone_verification' | 'password_reset';
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface LogoutRequest {
  revokeAll?: boolean;
}

export interface ForgotPasswordRequest {
  email?: string;
  phone?: string;
}

export interface ResetPasswordRequest {
  target: string;
  code: string;
  newPassword: string;
}

// === Auth Response DTOs ===

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  tokenType: string;
  user: UserInfo;
}

export interface MessageResponse {
  message: string;
}

export interface GoogleAuthURLResponse {
  url: string;
}

export interface OTPResponse {
  message: string;
  expiresAt: string;
  expiresIn: number;
}

// === User DTOs ===

export interface UserInfo {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phone?: string;
  avatar?: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  roles: string[];
  metadata?: string;
}

export interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  avatar?: string;
}

export interface ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}

export interface SetPasswordRequest {
  password: string;
}

// === Session Types ===

export interface Session {
  id: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
  expiresAt: string;
  lastActiveAt: string;
  createdAt: string;
}

export interface LinkedAccount {
  provider: string;
  email: string;
  linkedAt: string;
}

// === Admin User DTOs ===

export interface AdminUser {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phone?: string;
  avatar?: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  isActive: boolean;
  isSuperAdmin: boolean;
  lastLoginAt?: string;
  lastLoginIP?: string;
  failedAttempts: number;
  lockedUntil?: string;
  roles: string[];
  createdAt: string;
  updatedAt: string;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
  roleIds?: string[];
  isActive?: boolean;
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  phone?: string;
  isActive?: boolean;
  emailVerified?: boolean;
  phoneVerified?: boolean;
  roleIds?: string[];
}

export interface ListUsersParams {
  page?: number;
  pageSize?: number;
  search?: string;
  roleId?: string;
  isActive?: boolean;
}

export interface PaginatedUsersResponse {
  data: AdminUser[];
  meta: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

// === Role & Permission DTOs ===

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: Permission[];
  isSystem: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Permission {
  id: string;
  name: string;
  description?: string;
  resource: string;
  action: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissionIds?: string[];
}

export interface UpdateRoleRequest {
  name: string;
  description?: string;
  permissionIds?: string[];
}

export interface CreatePermissionRequest {
  name: string;
  description?: string;
  resource: string;
  action: string;
}

export interface UpdatePermissionRequest {
  name: string;
  description?: string;
  resource: string;
  action: string;
}

// === Service Auth DTOs ===

export interface ServiceAuthRequest {
  clientId: string;
  clientSecret: string;
}

export interface ServiceAuthResponse {
  accessToken: string;
  expiresIn: number;
  tokenType: string;
}

export interface CreateServiceClientRequest {
  name: string;
  scopes?: string[];
  description?: string;
}

export interface ServiceClient {
  id?: string;
  clientId: string;
  clientSecret?: string;
  name: string;
  scopes: string[] | string;
  description?: string;
  isActive?: boolean;
  message?: string;
  lastUsedAt?: string;
  createdAt?: string;
}

// === Generic Types ===

export interface ApiError {
  error: string;
  code: number;
  message: string;
  details?: Record<string, unknown>;
}

export interface TokenValidationResponse {
  valid: boolean;
  userId?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  scopes?: string[];
  expiresAt?: number;
  tokenType: 'user' | 'service';
  clientId?: string;
  serviceName?: string;
}
