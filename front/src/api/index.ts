/**
 * API exports
 * Centralized export of all API services
 */

export { api, apiClient, type ApiError, type ApiResponse } from './client';
export { BaseApi } from './base';

// Services
export { authApi, accountApi } from './services/auth';
export { userApi } from './services/user';
export { adminApi } from './services/admin';

// Types
export type {
  UserInfo,
  AuthResponse,
  LoginRequest,
  RegisterRequest,
  SendOTPRequest,
  VerifyOTPRequest,
  ResetPasswordRequest,
  ForgotPasswordRequest,
  MessageResponse,
  OTPResponse,
  Session,
  LinkedAccount,
  AdminUser,
  CreateUserRequest,
  UpdateUserRequest,
  Role,
  Permission,
  CreateRoleRequest,
  UpdateRoleRequest,
  CreatePermissionRequest,
  UpdatePermissionRequest,
  ServiceClient,
  CreateServiceClientRequest,
  PaginatedUsersResponse,
  ListUsersParams,
} from '@/types/auth';
