/**
 * Application configuration
 * Contains environment variables and app-wide settings
 */

function getApiBaseUrl(): string {
  if (typeof window !== 'undefined') {
    if (process.env.NEXT_PUBLIC_AUTH_API_BASE_URL) {
      return process.env.NEXT_PUBLIC_AUTH_API_BASE_URL;
    }
    if (process.env.NEXT_PUBLIC_API_URL) {
      return process.env.NEXT_PUBLIC_API_URL;
    }
    // In browser: use relative /v1 path so requests flow through current origin (e.g. gateway)
    return '/v1';
  }
  return (
    process.env.NEXT_PUBLIC_AUTH_API_BASE_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    'http://minisource-auth-backend:9001/v1'
  );
}

export const config = {
  app: {
    name: process.env.NEXT_PUBLIC_APP_NAME || 'Minisource Auth',
    url: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3003',
    version: process.env.NEXT_PUBLIC_APP_VERSION || '1.0.0',
  },
  api: {
    get baseUrl() {
      return getApiBaseUrl();
    },
    timeout: Number(process.env.NEXT_PUBLIC_API_TIMEOUT) || 30000,
  },
  auth: {
    enableGoogle: process.env.NEXT_PUBLIC_AUTH_ENABLE_GOOGLE !== 'false',
    enableRegister: process.env.NEXT_PUBLIC_AUTH_ENABLE_REGISTER !== 'false',
    enableOtp: process.env.NEXT_PUBLIC_AUTH_ENABLE_OTP !== 'false',
    tokenStorage: process.env.NEXT_PUBLIC_AUTH_TOKEN_STORAGE || 'localStorage',
  },
  features: {
    analytics: process.env.NEXT_PUBLIC_ENABLE_ANALYTICS === 'true',
    pwa: process.env.NEXT_PUBLIC_ENABLE_PWA === 'true',
  },
} as const;

export type Config = typeof config;
