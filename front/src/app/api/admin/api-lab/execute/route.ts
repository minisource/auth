import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';

// Approved operations catalog (Security boundary)
interface ApprovedOperation {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  sensitive?: boolean;
}

const APPROVED_OPERATIONS: Record<string, ApprovedOperation> = {
  'auth.login': { method: 'POST', path: '/v1/auth/login', sensitive: true },
  'auth.logout': { method: 'POST', path: '/v1/auth/logout' },
  'auth.otp.send': { method: 'POST', path: '/v1/auth/otp/send' },
  'auth.otp.verify': { method: 'POST', path: '/v1/auth/otp/verify', sensitive: true },
  'auth.forgot-password': { method: 'POST', path: '/v1/auth/forgot-password' },
  'auth.reset-password': { method: 'POST', path: '/v1/auth/reset-password', sensitive: true },
  'auth.introspect': { method: 'POST', path: '/v1/auth/introspect', sensitive: true },
  'auth.userinfo': { method: 'GET', path: '/v1/auth/userinfo' },
  'users.me': { method: 'GET', path: '/v1/users/me' },
  'admin.health': { method: 'GET', path: '/health' },
  'admin.ready': { method: 'GET', path: '/ready' },
  'admin.tools.introspect': { method: 'POST', path: '/v1/admin/tools/introspect-token' },
  'admin.tools.check-permission': { method: 'POST', path: '/v1/admin/tools/check-permission' },
  'admin.tools.jwks-status': { method: 'GET', path: '/v1/admin/tools/jwks-status' },
  'admin.tools.health': { method: 'GET', path: '/v1/admin/tools/health' },
};

// Sensitive fields to redact recursively
const SENSITIVE_KEYS = new Set([
  'password',
  'current_password',
  'new_password',
  'otp',
  'code',
  'token',
  'accesstoken',
  'refreshtoken',
  'access_token',
  'refresh_token',
  'client_secret',
  'secret',
  'api_key',
  'authorization',
  'cookie',
  'set-cookie',
]);

// Helper to recursively redact sensitive data
function redact(val: any): any {
  if (val === null || val === undefined) return val;
  if (Array.isArray(val)) {
    return val.map(redact);
  }
  if (typeof val === 'object') {
    const copy: Record<string, any> = {};
    for (const key of Object.keys(val)) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_KEYS.has(lowerKey)) {
        copy[key] = '••••••••';
      } else {
        copy[key] = redact(val[key]);
      }
    }
    return copy;
  }
  return val;
}

export async function POST(req: NextRequest) {
  const timestamp = new Date().toISOString();
  const requestId = req.headers.get('x-request-id') || `req-${Math.random().toString(36).substr(2, 9)}`;
  const correlationId = req.headers.get('x-correlation-id') || requestId;

  // 1. Get and Validate Admin Authorization
  const authHeader = req.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return NextResponse.json(
      { success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } },
      { status: 401 }
    );
  }
  const adminToken = authHeader.substring(7);

  const rawBaseUrl =
    process.env.AUTH_API_BASE_URL ||
    process.env.NEXT_PUBLIC_AUTH_API_BASE_URL ||
    'http://127.0.0.1:9001/v1';
  const backendBaseUrl = rawBaseUrl.replace(/\/v1\/?$/, '');

  let adminProfile: any = null;
  try {
    const profileRes = await axios.get(`${backendBaseUrl}/v1/users/me`, {
      headers: {
        Authorization: authHeader,
        'X-Request-ID': requestId,
        'X-Correlation-ID': correlationId,
      },
      timeout: 5000,
    });
    adminProfile = profileRes.data?.data || profileRes.data;
  } catch (err: any) {
    console.error(`[API Lab Audit] [${timestamp}] Auth validation failed for request ${requestId}:`, err.message);
    return NextResponse.json(
      { success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid or expired session' } },
      { status: 401 }
    );
  }

  const roles = adminProfile?.roles || [];
  const isAdmin = roles.includes('admin') || roles.includes('super_admin');
  if (!isAdmin) {
    console.warn(`[API Lab Audit] [${timestamp}] Forbidden access attempt by ${adminProfile?.email || 'unknown'} (roles: ${JSON.stringify(roles)})`);
    return NextResponse.json(
      { success: false, error: { code: 'FORBIDDEN', message: 'Admin access required' } },
      { status: 403 }
    );
  }

  // 2. Parse and Validate Request Body
  let body: any;
  try {
    body = await req.json();
  } catch (e) {
    return NextResponse.json(
      { success: false, error: { code: 'BAD_REQUEST', message: 'Invalid JSON body' } },
      { status: 400 }
    );
  }

  const { operationId, input, authMode, customToken, headers: reqHeaders = {} } = body;
  const operation = APPROVED_OPERATIONS[operationId];

  if (!operation) {
    return NextResponse.json(
      { success: false, error: { code: 'BAD_REQUEST', message: `Unknown or forbidden operation: ${operationId}` } },
      { status: 400 }
    );
  }

  // 3. Prepare Final Request Configuration
  const targetUrl = `${backendBaseUrl}${operation.path}`;
  const finalHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Request-ID': requestId,
    'X-Correlation-ID': correlationId,
  };

  // Extract correlation & trace propagation headers if present
  const traceparent = req.headers.get('traceparent');
  if (traceparent) finalHeaders['traceparent'] = traceparent;
  const tracestate = req.headers.get('tracestate');
  if (tracestate) finalHeaders['tracestate'] = tracestate;
  const baggage = req.headers.get('baggage');
  if (baggage) finalHeaders['baggage'] = baggage;

  // Allow only explicitly allowed custom headers
  const allowedHeaders = ['accept-language', 'x-language', 'idempotency-key'];
  for (const key of Object.keys(reqHeaders)) {
    const lowerKey = key.toLowerCase();
    if (allowedHeaders.includes(lowerKey)) {
      finalHeaders[key] = reqHeaders[key];
    }
  }

  // Inject Authorization based on authMode
  if (authMode === 'current-session') {
    finalHeaders['Authorization'] = `Bearer ${adminToken}`;
  } else if (authMode === 'bearer-token' && customToken) {
    finalHeaders['Authorization'] = `Bearer ${customToken}`;
  }

  // Sanitized view of headers and body for diagnostics response
  const sanitizedRequestHeaders = redact(finalHeaders);
  const sanitizedRequestBody = redact(input);

  // 4. Execute the Call
  const startTime = performance.now();
  let responseData: any = null;
  let responseHeaders: Record<string, string> = {};
  let statusCode = 500;
  let duration = 0;
  let isSuccess = false;
  let errorPayload: any = null;

  try {
    const res = await axios({
      method: operation.method,
      url: targetUrl,
      data: operation.method !== 'GET' ? input : undefined,
      headers: finalHeaders,
      timeout: 10000, // 10s timeout
      validateStatus: () => true, // Do not throw on 4xx/5xx to inspect output
    });

    statusCode = res.status;
    responseHeaders = {};
    if (res.headers) {
      for (const [key, value] of Object.entries(res.headers)) {
        const safeResponseHeaders = ['content-type', 'x-request-id', 'x-correlation-id', 'traceparent'];
        if (safeResponseHeaders.includes(key.toLowerCase())) {
          responseHeaders[key] = value as string;
        }
      }
    }

    responseData = res.data;
    duration = Math.round(performance.now() - startTime);
    isSuccess = statusCode >= 200 && statusCode < 300;
  } catch (err: any) {
    duration = Math.round(performance.now() - startTime);
    statusCode = err.response?.status || 500;
    errorPayload = {
      code: err.code || 'CONNECTION_ERROR',
      message: err.message || 'Failed to connect to the backend service',
    };
  }

  // 5. Redact Response
  const sanitizedResponseHeaders = redact(responseHeaders);
  const sanitizedResponseBody = redact(responseData || errorPayload);

  // 6. Security Audit Event Logging (Structured JSON format for operations team)
  const auditEvent = {
    event: 'API_LAB_EXECUTION',
    timestamp,
    adminEmail: adminProfile?.email,
    adminId: adminProfile?.id,
    operationId,
    targetUrl: operation.path,
    method: operation.method,
    statusCode,
    durationMs: duration,
    isSuccess,
    requestId,
    correlationId,
  };
  console.log(`[API Lab Audit]`, JSON.stringify(auditEvent));

  // 7. Return complete diagnostic response
  return NextResponse.json({
    success: isSuccess,
    statusCode,
    duration,
    requestId,
    correlationId,
    request: {
      url: operation.path,
      method: operation.method,
      headers: sanitizedRequestHeaders,
      body: sanitizedRequestBody,
    },
    response: {
      headers: sanitizedResponseHeaders,
      body: sanitizedResponseBody,
    },
  });
}
