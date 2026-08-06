import { api } from '../client';
import { BaseApi } from '../base';
import type {
  UserInfo,
  UpdateProfileRequest,
  ChangePasswordRequest,
  SetPasswordRequest,
  Session,
  LinkedAccount,
  MessageResponse,
} from '@/types/auth';

/**
 * User API service - profile and session management
 */
class UserApi extends BaseApi {
  constructor() {
    super('/users');
  }

  /**
   * Get current user profile
   * GET /api/v1/users/me
   */
  async getProfile(): Promise<UserInfo> {
    return api.get<UserInfo>(this.url('/me'));
  }

  /**
   * Update current user profile
   * PUT /api/v1/users/me
   */
  async updateProfile(data: UpdateProfileRequest): Promise<UserInfo> {
    return api.put<UserInfo>(this.url('/me'), data);
  }

  /**
   * Change password
   * PUT /api/v1/users/me/password
   */
  async changePassword(data: ChangePasswordRequest): Promise<MessageResponse> {
    return api.put<MessageResponse>(this.url('/me/password'), data);
  }

  /**
   * Set password (for OTP users)
   * POST /api/v1/users/me/password/set
   */
  async setPassword(data: SetPasswordRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/me/password/set'), data);
  }

  /**
   * Get active sessions
   * GET /api/v1/users/me/sessions
   */
  async getSessions(): Promise<Session[]> {
    return api.get<Session[]>(this.url('/me/sessions'));
  }

  /**
   * Get linked OAuth accounts
   * GET /api/v1/users/me/linked-accounts
   */
  async getLinkedAccounts(): Promise<LinkedAccount[]> {
    return api.get<LinkedAccount[]>(this.url('/me/linked-accounts'));
  }

  /**
   * Unlink Google account
   * DELETE /api/v1/users/me/linked-accounts/google
   */
  async unlinkGoogle(): Promise<MessageResponse> {
    return api.delete<MessageResponse>(this.url('/me/linked-accounts/google'));
  }
}

export const userApi = new UserApi();
