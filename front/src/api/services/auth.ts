import { api } from '../client';
import { BaseApi } from '../base';
import type {
  LoginRequest,
  RegisterRequest,
  SendOTPRequest,
  VerifyOTPRequest,
  RefreshTokenRequest,
  LogoutRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  AuthResponse,
  MessageResponse,
  GoogleAuthURLResponse,
  OTPResponse,
} from '@/types/auth';

/**
 * Auth API service - all authentication endpoints
 */
class AuthApi extends BaseApi {
  constructor() {
    super('/auth');
  }

  /**
   * Login with email and password
   * POST /api/v1/auth/login
   */
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    return api.post<AuthResponse>(this.url('/login'), credentials);
  }

  /**
   * Register a new user
   * POST /api/v1/auth/register
   */
  async register(data: RegisterRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/register'), data);
  }

  /**
   * Send OTP to phone or email
   * POST /api/v1/auth/otp/send
   */
  async sendOTP(data: SendOTPRequest): Promise<OTPResponse> {
    return api.post<OTPResponse>(this.url('/otp/send'), data);
  }

  /**
   * Verify OTP and login
   * POST /api/v1/auth/otp/verify
   */
  async verifyOTP(data: VerifyOTPRequest): Promise<AuthResponse> {
    return api.post<AuthResponse>(this.url('/otp/verify'), data);
  }

  /**
   * Refresh access token
   * POST /api/v1/auth/refresh
   */
  async refreshToken(data: RefreshTokenRequest): Promise<AuthResponse> {
    return api.post<AuthResponse>(this.url('/refresh'), data);
  }

  /**
   * Logout user
   * POST /api/v1/auth/logout
   */
  async logout(data?: LogoutRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/logout'), data || {});
  }

  /**
   * Get Google OAuth URL
   * GET /api/v1/auth/google
   */
  async getGoogleAuthURL(state?: string): Promise<GoogleAuthURLResponse> {
    const params = state ? { state } : undefined;
    return api.get<GoogleAuthURLResponse>(this.url('/google'), params as Record<string, unknown>);
  }

  /**
   * Handle Google OAuth callback
   * GET /api/v1/auth/google/callback
   */
  async googleCallback(code: string): Promise<AuthResponse> {
    return api.get<AuthResponse>(this.url(`/google/callback?code=${code}`));
  }

  /**
   * Request password reset (send OTP)
   * POST /api/v1/auth/forgot-password
   */
  async forgotPassword(data: ForgotPasswordRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/forgot-password'), data);
  }

  /**
   * Reset password with OTP
   * POST /api/v1/auth/reset-password
   */
  async resetPassword(data: ResetPasswordRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/reset-password'), data);
  }

  /**
   * Verify email with OTP
   * POST /api/v1/auth/verify-email
   */
  async verifyEmail(data: VerifyOTPRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/verify-email'), data);
  }

  /**
   * Resend verification code
   * POST /api/v1/auth/resend-verification
   */
  async resendVerification(data: SendOTPRequest): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/resend-verification'), data);
  }

  /**
   * Google mobile login
   * POST /api/v1/auth/google/mobile
   */
  async googleMobileLogin(data: { idToken: string }): Promise<AuthResponse> {
    return api.post<AuthResponse>(this.url('/google/mobile'), data);
  }

  /**
   * Introspect token (public)
   * POST /api/v1/auth/introspect
   */
  async introspectToken(token: string): Promise<{ active: boolean; sub?: string; exp?: number }> {
    return api.post(this.url('/introspect'), { token });
  }

  /**
   * Get userinfo (protected)
   * GET /api/v1/auth/userinfo
   */
  async getUserinfo(): Promise<Record<string, unknown>> {
    return api.get(this.url('/userinfo'));
  }
}

export const authApi = new AuthApi();

// ==================== Account API (phone verification) ====================

/**
 * Account API — phone verification and identity management
 * Base: /account
 */
class AccountApi extends BaseApi {
  constructor() {
    super('/account');
  }

  /**
   * Start phone verification
   * POST /api/v1/account/phone/start
   */
  async phoneStart(data: { phone: string }): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/phone/start'), data);
  }

  /**
   * Verify phone with OTP
   * POST /api/v1/account/phone/verify
   */
  async phoneVerify(data: { phone: string; code: string }): Promise<MessageResponse> {
    return api.post<MessageResponse>(this.url('/phone/verify'), data);
  }
}

export const accountApi = new AccountApi();
