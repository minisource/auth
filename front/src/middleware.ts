import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Next.js basePath — the auth app is served at /auth via the gateway
 * (mirrors the notifier frontend pattern: basePath '/notifier').
 *
 * Middleware redirect targets are built manually, so they must include the
 * basePath. Pattern matching is done against the basePath-stripped path to
 * stay robust regardless of whether the runtime includes the prefix.
 */
const BASE_PATH = '/auth';

/**
 * Protected routes that require authentication.
 * All routes under /dashboard and /admin need auth.
 */
const PROTECTED_PATTERNS = ['/dashboard', '/admin', '/profile'];

/**
 * Public routes that should redirect to dashboard if already authenticated.
 */
const AUTH_ROUTES = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-email'];

/**
 * Path prefixes served by OTHER MiniSource frontends behind the gateway.
 * Redirect targets for these must NOT be prefixed with the auth basePath.
 */
const CROSS_APP_PREFIXES = [
  '/notifier/',
  '/log/',
  '/scheduler/',
  '/storage/',
  '/comment/',
  '/ticket/',
  '/feedback/',
];

function stripBasePath(pathname: string): string {
  if (pathname === BASE_PATH) return '/';
  if (pathname.startsWith(`${BASE_PATH}/`)) return pathname.slice(BASE_PATH.length);
  return pathname;
}

function isCrossAppPath(path: string): boolean {
  // Match both the bare prefix (e.g. "/notifier") and any sub-path under it
  // (e.g. "/notifier/dashboard"), mirroring use-auth.ts.
  return CROSS_APP_PREFIXES.some((prefix) => {
    const bare = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    return path === bare || path.startsWith(prefix);
  });
}

function resolveRedirectTarget(returnUrl: string | null): string {
  if (!returnUrl) return `${BASE_PATH}/dashboard`;
  if (returnUrl.startsWith('http://') || returnUrl.startsWith('https://') || returnUrl.startsWith('//')) {
    return returnUrl;
  }
  if (isCrossAppPath(returnUrl) || returnUrl.startsWith(BASE_PATH)) return returnUrl;
  return `${BASE_PATH}${returnUrl}`;
}

/**
 * Middleware — runs on every request.
 *
 * Checks for an `auth` cookie (set by the client-side auth store)
 * to determine if the user is authenticated.
 *
 * - Protected routes without auth cookie → redirect to /auth/login
 * - Auth routes with auth cookie → redirect to /auth/dashboard
 */
export function middleware(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl;

  // Normalize path so matching is basePath-agnostic.
  const path = stripBasePath(pathname);

  // Skip middleware for API routes, static files, and Next.js internals
  if (
    path.startsWith('/_next') ||
    path.startsWith('/api') ||
    path.includes('.') ||
    path === '/favicon.ico'
  ) {
    return NextResponse.next();
  }

  const hasAuthCookie = request.cookies.has('auth');
  const isProtected = PROTECTED_PATTERNS.some((p) => path.startsWith(p));
  const isAuthRoute = AUTH_ROUTES.some((r) => path === r);

  // Protected route without auth → redirect to login
  if (isProtected && !hasAuthCookie) {
    const loginUrl = new URL(`${BASE_PATH}/login`, request.url);
    loginUrl.searchParams.set('returnUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Auth route WITH auth → redirect to dashboard
  if (isAuthRoute && hasAuthCookie) {
    const returnUrl = searchParams.get('returnUrl');
    const dashboardUrl = new URL(resolveRedirectTarget(returnUrl), request.url);
    return NextResponse.redirect(dashboardUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image).*)',
  ],
};
