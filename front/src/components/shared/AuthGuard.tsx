'use client';

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuthStore } from '@/stores';
import { LoadingState } from '@minisource/ui';

interface AuthGuardProps {
  children: React.ReactNode;
  /** Fallback shown while auth state is hydrating */
  fallback?: React.ReactNode;
}

/**
 * AuthGuard — protects authenticated routes.
 *
 * Waits for Zustand persist hydration to complete, then:
 * - If authenticated → renders children
 * - If NOT authenticated → redirects to /login with returnUrl
 *
 * Prevents flash of unauthenticated content on page refresh.
 */
export function AuthGuard({ children, fallback }: AuthGuardProps) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const _hasHydrated = useAuthStore((s) => s._hasHydrated);
  const router = useRouter();
  const pathname = usePathname();

  // Safeguard: Ensure _hasHydrated is true on client mount if tokens exist in storage
  useEffect(() => {
    if (typeof window === 'undefined') return;

    if (!_hasHydrated) {
      const hasToken = Boolean(
        window.localStorage.getItem('accessToken') || window.sessionStorage.getItem('accessToken')
      );
      const isHydrated = useAuthStore.persist?.hasHydrated?.() ?? false;

      if (hasToken || isHydrated) {
        useAuthStore.setState({ _hasHydrated: true });
        if (hasToken && !isAuthenticated) {
          document.cookie = 'auth=1; path=/; samesite=lax';
          useAuthStore.setState({ isAuthenticated: true });
        }
      }
    }
  }, [_hasHydrated, isAuthenticated]);

  useEffect(() => {
    if (!_hasHydrated) return;

    if (!isAuthenticated) {
      const returnUrl = pathname && pathname !== '/login' ? `?returnUrl=${encodeURIComponent(pathname)}` : '';
      router.replace(`/login${returnUrl}`);
    }
  }, [_hasHydrated, isAuthenticated, router, pathname]);

  // Still hydrating — show fallback (or default loading spinner)
  if (!_hasHydrated) {
    return fallback ?? (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingState size="lg" message="Loading..." />
      </div>
    );
  }

  // Hydrated but not authenticated — show fallback briefly while redirecting
  if (!isAuthenticated) {
    return fallback ?? (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingState size="lg" message="Redirecting..." />
      </div>
    );
  }

  return <>{children}</>;
}
