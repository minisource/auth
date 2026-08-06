/**
 * Canonical Error Model for MiniSource Auth Frontend
 */

export type ErrorCategory =
  | 'network'
  | 'offline'
  | 'timeout'
  | 'cancelled'
  | 'authentication'
  | 'authorization'
  | 'validation'
  | 'not_found'
  | 'conflict'
  | 'rate_limit'
  | 'server'
  | 'maintenance'
  | 'tenant'
  | 'unknown';

export type ErrorSeverity = 'info' | 'warning' | 'error' | 'critical';

export interface AppError {
  category: ErrorCategory;
  code: string;
  message: string;
  userMessage: string;
  status?: number;
  severity: ErrorSeverity;
  requestId?: string;
  correlationId?: string;
  timestamp: string;
  fieldErrors?: Record<string, string[]>;
  retryable: boolean;
  retryAfter?: number;
  operation?: string;
  resource?: string;
  cause?: unknown;
}

/**
 * Normalizes any error (Axios, Fetch, Error, string, unknown) into a canonical AppError.
 */
export function normalizeError(error: unknown, context?: string): AppError {
  const timestamp = new Date().toISOString();

  // If already an AppError, return directly
  if (isAppError(error)) {
    return context ? { ...error, operation: error.operation || context } : error;
  }

  // Handle Axios / Network / HTTP Errors
  if (typeof error === 'object' && error !== null) {
    const err = error as Record<string, any>;

    // Handle Network Disconnect / Connection Refused (no response received)
    const isNetwork =
      err.code === 'ERR_NETWORK' ||
      err.code === 'ECONNREFUSED' ||
      err.message?.includes('Network Error') ||
      err.message?.includes('Failed to fetch') ||
      (!err.response && (err.request || err.code === 'ENOTFOUND'));

    if (isNetwork) {
      const isOffline = typeof navigator !== 'undefined' && !navigator.onLine;
      return {
        category: isOffline ? 'offline' : 'network',
        code: isOffline ? 'BROWSER_OFFLINE' : 'BACKEND_UNAVAILABLE',
        message: err.message || 'Connection refused or backend unavailable',
        userMessage: isOffline
          ? 'Your browser is currently offline. Please check your network connection.'
          : 'Could not connect to the Auth API service. The backend server may be offline.',
        status: undefined,
        severity: 'critical',
        requestId: err.config?.headers?.['X-Request-ID'],
        timestamp,
        retryable: true,
        operation: context,
        cause: error,
      };
    }

    // Timeout
    if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
      return {
        category: 'timeout',
        code: 'REQUEST_TIMEOUT',
        message: err.message || 'Request timed out',
        userMessage: 'The server took too long to respond. Please try again.',
        status: 408,
        severity: 'warning',
        timestamp,
        retryable: true,
        operation: context,
        cause: error,
      };
    }

    // Cancelled
    if (err.code === 'ERR_CANCELED' || err.name === 'AbortError') {
      return {
        category: 'cancelled',
        code: 'REQUEST_CANCELLED',
        message: 'Request was cancelled',
        userMessage: 'Request cancelled',
        severity: 'info',
        timestamp,
        retryable: false,
        operation: context,
      };
    }

    // HTTP Response Errors
    if (err.response) {
      const status = err.response.status as number;
      const data = err.response.data || {};
      const errObj = typeof data.error === 'object' && data.error !== null ? data.error : {};
      const backendMessage = data.message || errObj.message || data.detail || err.message || 'HTTP Error';
      const backendCode = data.code || errObj.code || `HTTP_${status}`;
      const requestId = data.requestId || err.response.headers?.['x-request-id'];

      switch (status) {
        case 400:
          return {
            category: 'validation',
            code: backendCode,
            message: backendMessage,
            userMessage: data.userMessage || backendMessage || 'Invalid request details provided.',
            status: 400,
            severity: 'warning',
            requestId,
            fieldErrors: data.errors || data.fieldErrors,
            timestamp,
            retryable: false,
            operation: context,
          };

        case 401:
          return {
            category: 'authentication',
            code: backendCode || 'UNAUTHENTICATED',
            message: backendMessage,
            userMessage: data.userMessage || backendMessage || 'Invalid credentials or session expired.',
            status: 401,
            severity: 'warning',
            requestId,
            timestamp,
            retryable: false,
            operation: context,
          };

        case 403:
          return {
            category: 'authorization',
            code: backendCode || 'ACCESS_DENIED',
            message: backendMessage,
            userMessage: 'You do not have required permissions to perform this action.',
            status: 403,
            severity: 'warning',
            requestId,
            timestamp,
            retryable: false,
            operation: context,
          };

        case 404:
          return {
            category: 'not_found',
            code: backendCode || 'RESOURCE_NOT_FOUND',
            message: backendMessage,
            userMessage: 'The requested item or resource could not be found.',
            status: 404,
            severity: 'info',
            requestId,
            timestamp,
            retryable: false,
            operation: context,
          };

        case 409:
          return {
            category: 'conflict',
            code: backendCode || 'RESOURCE_CONFLICT',
            message: backendMessage,
            userMessage: backendMessage || 'A resource conflict occurred.',
            status: 409,
            severity: 'warning',
            requestId,
            fieldErrors: data.errors,
            timestamp,
            retryable: false,
            operation: context,
          };

        case 422:
          return {
            category: 'validation',
            code: backendCode || 'VALIDATION_FAILED',
            message: backendMessage,
            userMessage: 'Validation failed for submitted data.',
            status: 422,
            severity: 'warning',
            requestId,
            fieldErrors: data.errors || data.fieldErrors,
            timestamp,
            retryable: false,
            operation: context,
          };

        case 429:
          return {
            category: 'rate_limit',
            code: backendCode || 'RATE_LIMITED',
            message: backendMessage,
            userMessage: 'Too many requests. Please wait a moment before trying again.',
            status: 429,
            severity: 'warning',
            requestId,
            retryAfter: Number(err.response.headers?.['retry-after']) || 60,
            timestamp,
            retryable: true,
            operation: context,
          };

        case 500:
        case 502:
        case 503:
        case 504:
          return {
            category: 'server',
            code: backendCode || `SERVER_ERROR_${status}`,
            message: backendMessage,
            userMessage: 'The Auth backend server encountered an error. Please try again later.',
            status,
            severity: 'error',
            requestId,
            timestamp,
            retryable: true,
            operation: context,
          };
      }
    }
  }

  // Fallback for unknown errors
  const message = error instanceof Error ? error.message : String(error);
  return {
    category: 'unknown',
    code: 'UNKNOWN_ERROR',
    message,
    userMessage: 'An unexpected error occurred. Please try again.',
    severity: 'error',
    timestamp,
    retryable: true,
    operation: context,
    cause: error,
  };
}

export function isAppError(error: unknown): error is AppError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'category' in error &&
    'code' in error &&
    'userMessage' in error
  );
}

export function isNetworkError(error: AppError): boolean {
  return error.category === 'network' || error.category === 'offline';
}

export function isAuthError(error: AppError): boolean {
  return error.category === 'authentication';
}

export function isForbiddenError(error: AppError): boolean {
  return error.category === 'authorization';
}

export function isServerError(error: AppError): boolean {
  return error.category === 'server' || error.category === 'network' || error.category === 'offline';
}

export function isRetryableError(error: AppError): boolean {
  return error.retryable;
}
