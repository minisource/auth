import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const BASE_PATH = '/auth';
const PROTECTED_PATTERNS = ['/dashboard', '/admin', '/profile'];
const AUTH_ROUTES = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-email'];
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
  return CROSS_APP_PREFIXES.some((prefix) => {
    const bare = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    return path === bare || path.startsWith(prefix);
  });
}

function resolveRedirectTarget(returnUrl: string | null): string {
  if (!returnUrl) return '/dashboard';
  if (returnUrl.startsWith('http://') || returnUrl.startsWith('https://') || returnUrl.startsWith('//')) {
    return returnUrl;
  }
  if (isCrossAppPath(returnUrl)) return returnUrl;
  if (returnUrl.startsWith(BASE_PATH)) return returnUrl.slice(BASE_PATH.length) || '/dashboard';
  return returnUrl;
}

export function proxy(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl;
  const path = stripBasePath(pathname);

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
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/login';
    loginUrl.searchParams.set('returnUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Auth route WITH auth → redirect to dashboard
  if (isAuthRoute && hasAuthCookie) {
    const returnUrl = searchParams.get('returnUrl');
    const target = resolveRedirectTarget(returnUrl);
    if (target.startsWith('http://') || target.startsWith('https://') || isCrossAppPath(target)) {
      return NextResponse.redirect(new URL(target, request.url));
    }
    const dashboardUrl = request.nextUrl.clone();
    dashboardUrl.pathname = target;
    return NextResponse.redirect(dashboardUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image).*)'],
};
