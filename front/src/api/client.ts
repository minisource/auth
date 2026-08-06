import axios, {
  AxiosError,
  AxiosInstance,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from 'axios';
import { config } from '@/config';
import {
  getAcceptLanguageHeader,
  getLanguageHeader,
  resolveLanguage,
} from '@/shared/i18n/language';
import { normalizeError } from '@/shared/errors/app-error';
import { useAuthStore, useTenantStore } from '@/stores';
import { propagation, context } from '@opentelemetry/api';

/**
 * Legacy API Error interface for backward compatibility
 */
export interface ApiError {
  message: string;
  code?: string;
  status?: number;
  details?: Record<string, unknown>;
}

/**
 * API Response wrapper type
 */
export interface ApiResponse<T> {
  data: T;
  message?: string;
  success: boolean;
}

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: unknown) => void;
}> = [];

function processQueue(error: unknown, token: string | null) {
  failedQueue.forEach((prom) => {
    if (error || !token) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
}

function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null;
  const storeToken = useAuthStore.getState().tokens?.accessToken;
  if (storeToken) return storeToken;
  return localStorage.getItem('accessToken') || sessionStorage.getItem('accessToken');
}

function getRefreshToken(): string | null {
  if (typeof window === 'undefined') return null;
  const storeToken = useAuthStore.getState().tokens?.refreshToken;
  if (storeToken) return storeToken;
  return localStorage.getItem('refreshToken') || sessionStorage.getItem('refreshToken');
}

function setTokens(accessToken: string, refreshToken: string) {
  if (typeof window === 'undefined') return;
  useAuthStore.getState().updateTokens({ accessToken, refreshToken });
}

function clearTokens() {
  if (typeof window === 'undefined') return;
  useAuthStore.getState().clearAuth();
}

/**
 * Creates and configures an Axios instance with interceptors
 */
function createApiClient(): AxiosInstance {
  const client = axios.create({
    baseURL: config.api.baseUrl,
    timeout: config.api.timeout,
    headers: {
      'Content-Type': 'application/json',
    },
    withCredentials: false,
  });

  // Request interceptor — attach access token, tenant ID & language headers
  client.interceptors.request.use(
    (requestConfig: InternalAxiosRequestConfig) => {
      requestConfig.baseURL = config.api.baseUrl;
      const token = getAccessToken();
      if (token && requestConfig.headers) {
        requestConfig.headers.Authorization = `Bearer ${token}`;
      }

      // Attach active Tenant ID header if an organization is selected
      const activeTenant = useTenantStore.getState().activeTenant;
      if (activeTenant?.id && activeTenant.id !== 'all' && requestConfig.headers) {
        requestConfig.headers['X-Tenant-ID'] = activeTenant.id;
      }

      const lang = resolveLanguage();
      if (requestConfig.headers) {
        requestConfig.headers['X-Language'] = getLanguageHeader(lang);
        requestConfig.headers['Accept-Language'] = getAcceptLanguageHeader(lang);

        // Inject trace context headers (works on server-side and browser if OTel is active)
        const traceHeaders: Record<string, string> = {};
        propagation.inject(context.active(), traceHeaders);
        for (const [k, v] of Object.entries(traceHeaders)) {
          requestConfig.headers[k] = v;
        }
      }
      return requestConfig;
    },
    (error: AxiosError) => Promise.reject(normalizeError(error))
  );

  // Response interceptor — handle 401 with single-flight refresh
  client.interceptors.response.use(
    (response: AxiosResponse) => response,
    async (error: AxiosError<any>) => {
      const originalRequest = error.config as InternalAxiosRequestConfig & {
        _retry?: boolean;
      };

      const url = originalRequest?.url || '';
      const isAuthEndpoint =
        url.includes('/auth/login') ||
        url.includes('/auth/register') ||
        url.includes('/auth/refresh') ||
        url.includes('/auth/otp');

      // Controlled single-flight token refresh ONLY on HTTP 401
      if (error.response?.status === 401 && originalRequest && !isAuthEndpoint) {
        if (originalRequest._retry) {
          clearTokens();
          if (typeof window !== 'undefined') {
            window.location.href = '/auth/login';
          }
          return Promise.reject(normalizeError(error, url));
        }

        if (isRefreshing) {
          return new Promise<string>((resolve, reject) => {
            failedQueue.push({ resolve, reject });
          })
            .then((token) => {
              if (originalRequest.headers) {
                originalRequest.headers.Authorization = `Bearer ${token}`;
              }
              return client(originalRequest);
            })
            .catch((err) => Promise.reject(normalizeError(err, url)));
        }

        originalRequest._retry = true;
        isRefreshing = true;

        const refreshToken = getRefreshToken();
        if (!refreshToken) {
          isRefreshing = false;
          clearTokens();
          if (typeof window !== 'undefined') {
            window.location.href = '/auth/login';
          }
          return Promise.reject(normalizeError(error, url));
        }

        try {
          const response = await axios.post(
            `${config.api.baseUrl}/auth/refresh`,
            { refreshToken },
            { headers: { 'Content-Type': 'application/json' } }
          );

          const { accessToken, refreshToken: newRefreshToken } =
            response.data.data || response.data;

          setTokens(accessToken, newRefreshToken || refreshToken);
          processQueue(null, accessToken);

          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          }
          return client(originalRequest);
        } catch (refreshError: any) {
          processQueue(refreshError, null);
          // ONLY clear session if server explicitly returned 401/403 (invalid refresh token)
          // DO NOT clear session on Network Error or 5xx Backend Offline!
          if (refreshError?.response?.status === 401 || refreshError?.response?.status === 403) {
            clearTokens();
            if (typeof window !== 'undefined') {
              window.location.href = '/auth/login';
            }
          }
          return Promise.reject(normalizeError(refreshError, url));
        } finally {
          isRefreshing = false;
        }
      }

      // Return normalized AppError for all other errors (Network, 5xx, 403, 404, etc.)
      const normalized = normalizeError(error, url);
      return Promise.reject(normalized);
    }
  );

  return client;
}

export const apiClient = createApiClient();

function unwrapEnvelope<T>(res: AxiosResponse): T {
  const body = res.data;
  if (body && typeof body === 'object' && 'data' in body && body.data !== undefined) {
    return body.data as T;
  }
  return body as T;
}

export const api = {
  get: <T>(url: string, params?: Record<string, unknown>) =>
    apiClient.get<T>(url, { params }).then((res) => unwrapEnvelope<T>(res)),

  post: <T>(url: string, data?: unknown) =>
    apiClient.post<T>(url, data).then((res) => unwrapEnvelope<T>(res)),

  put: <T>(url: string, data?: unknown) =>
    apiClient.put<T>(url, data).then((res) => unwrapEnvelope<T>(res)),

  patch: <T>(url: string, data?: unknown) =>
    apiClient.patch<T>(url, data).then((res) => unwrapEnvelope<T>(res)),

  delete: <T>(url: string) =>
    apiClient.delete<T>(url).then((res) => unwrapEnvelope<T>(res)),
};
