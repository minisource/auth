import { create } from 'zustand';
import { persist, createJSONStorage, type StateStorage } from 'zustand/middleware';
import type { UserInfo } from '@/types/auth';

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

/**
 * Returns the storage backend based on rememberMe preference.
 * localStorage — persists across browser sessions (remember me checked)
 * sessionStorage — cleared when tab closes (remember me unchecked)
 */
function getTokenStorage(): Storage {
  if (typeof window === 'undefined') return null as unknown as Storage;
  const rememberMe = window.localStorage.getItem('rememberMe') !== 'false';
  return rememberMe ? window.localStorage : window.sessionStorage;
}

/**
 * Custom state storage that dynamically selects localStorage or sessionStorage
 * based on the rememberMe flag stored in localStorage.
 */
const dynamicStorage: StateStorage = {
  getItem: (name: string) => {
    try {
      if (typeof window === 'undefined') return null;
      const rememberMe = window.localStorage.getItem('rememberMe') !== 'false';
      const primary = rememberMe ? window.localStorage : window.sessionStorage;
      const secondary = rememberMe ? window.sessionStorage : window.localStorage;
      return primary.getItem(name) || secondary.getItem(name);
    } catch {
      return null;
    }
  },
  setItem: (name: string, value: string) => {
    try {
      const rememberMe = window.localStorage.getItem('rememberMe') !== 'false';
      if (rememberMe) {
        window.localStorage.setItem(name, value);
        window.sessionStorage.removeItem(name); // Clear stale data from other storage
      } else {
        window.sessionStorage.setItem(name, value);
        window.localStorage.removeItem(name); // Clear stale data from other storage
      }
    } catch {
      // Storage full or unavailable - ignore
    }
  },
  removeItem: (name: string) => {
    try {
      window.localStorage.removeItem(name);
      window.sessionStorage.removeItem(name);
    } catch {
      // Ignore
    }
  },
};

interface AuthState {
  // State
  user: UserInfo | null;
  tokens: AuthTokens | null;
  isAuthenticated: boolean;
  rememberMe: boolean;
  _hasHydrated: boolean;

  // Actions
  setAuth: (user: UserInfo, tokens: AuthTokens, rememberMe?: boolean) => void;
  clearAuth: () => void;
  updateUser: (user: Partial<UserInfo>) => void;
  updateTokens: (tokens: AuthTokens) => void;
  setRememberMe: (remember: boolean) => void;
  setHasHydrated: (v: boolean) => void;
  hasRole: (role: string) => boolean;
  hasAnyRole: (roles: string[]) => boolean;
  isAdmin: () => boolean;
}

/**
 * Auth store with persistence
 * Manages authentication state across the application
 */
export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      tokens: null,
      isAuthenticated: false,
      rememberMe: true,
      _hasHydrated: false,

      setHasHydrated: (v: boolean) => set({ _hasHydrated: v }),

      setAuth: (user, tokens, rememberMe?: boolean) => {
        const rm = rememberMe ?? get().rememberMe;
        if (typeof window !== 'undefined') {
          const storage = rm ? window.localStorage : window.sessionStorage;
          const otherStorage = rm ? window.sessionStorage : window.localStorage;
          storage.setItem('accessToken', tokens.accessToken);
          storage.setItem('refreshToken', tokens.refreshToken);
          otherStorage.removeItem('accessToken');
          otherStorage.removeItem('refreshToken');
          window.localStorage.setItem('rememberMe', String(rm));
          // Set auth cookie for server-side middleware
          const maxAge = rm ? 60 * 60 * 24 * 30 : undefined;
          document.cookie = `auth=1; path=/; samesite=lax${maxAge ? `; max-age=${maxAge}` : ''}`;
        }
        set({
          user,
          tokens,
          isAuthenticated: true,
          rememberMe: rm,
          _hasHydrated: true,
        });
      },

      clearAuth: () => {
        if (typeof window !== 'undefined') {
          window.localStorage.removeItem('accessToken');
          window.localStorage.removeItem('refreshToken');
          window.sessionStorage.removeItem('accessToken');
          window.sessionStorage.removeItem('refreshToken');
          window.localStorage.removeItem('auth-storage');
          window.sessionStorage.removeItem('auth-storage');
          // Remove auth cookie cleanly
          document.cookie = 'auth=; path=/; max-age=0; samesite=lax';
        }
        set({
          user: null,
          tokens: null,
          isAuthenticated: false,
        });
      },

      updateUser: (updates) =>
        set((state) => ({
          user: state.user ? { ...state.user, ...updates } : null,
        })),

      updateTokens: (tokens) => {
        const storage = getTokenStorage();
        if (typeof window !== 'undefined' && storage) {
          storage.setItem('accessToken', tokens.accessToken);
          storage.setItem('refreshToken', tokens.refreshToken);
          const rememberMe = window.localStorage.getItem('rememberMe') !== 'false';
          const maxAge = rememberMe ? 60 * 60 * 24 * 30 : undefined;
          document.cookie = `auth=1; path=/; samesite=lax${maxAge ? `; max-age=${maxAge}` : ''}`;
        }
        set({ tokens, isAuthenticated: true, _hasHydrated: true });
      },

      setRememberMe: (remember: boolean) => {
        if (typeof window !== 'undefined') {
          window.localStorage.setItem('rememberMe', String(remember));
        }
        set({ rememberMe: remember });
      },

      hasRole: (role: string) => {
        const { user } = get();
        if (!user || !user.roles) return false;
        return user.roles.includes(role) || user.roles.includes('super_admin');
      },

      hasAnyRole: (roles: string[]) => {
        const { user } = get();
        if (!user || !user.roles) return false;
        return roles.some((role) => user.roles.includes(role)) || user.roles.includes('super_admin');
      },

      isAdmin: () => {
        const { user } = get();
        if (!user || !user.roles) return false;
        return user.roles.includes('admin') || user.roles.includes('super_admin');
      },
    }),
    {
      name: 'auth-storage',
      storage: createJSONStorage(() => dynamicStorage),
      partialize: (state) => ({
        user: state.user,
        tokens: state.tokens,
        isAuthenticated: state.isAuthenticated,
        rememberMe: state.rememberMe,
      }),
      onRehydrateStorage: () => {
        return (state, error) => {
          const currentStore = useAuthStore.getState();
          // If in-memory state is already authenticated (e.g. setAuth called during login), preserve it!
          if (currentStore.isAuthenticated && currentStore.user && currentStore.tokens) {
            useAuthStore.setState({ _hasHydrated: true });
            return;
          }

          if (!error && state) {
            const hasRawTokens = typeof window !== 'undefined' && Boolean(
              window.localStorage.getItem('accessToken') || window.sessionStorage.getItem('accessToken')
            );
            const hasStoreTokens = Boolean(state.tokens?.accessToken);
            const valid = (hasRawTokens || hasStoreTokens);

            if (valid) {
              const rememberMe = state.rememberMe ?? true;
              const maxAge = rememberMe ? 60 * 60 * 24 * 30 : undefined;
              if (typeof window !== 'undefined') {
                document.cookie = `auth=1; path=/; samesite=lax${maxAge ? `; max-age=${maxAge}` : ''}`;
              }
              useAuthStore.setState({
                user: state.user,
                tokens: state.tokens || {
                  accessToken: (typeof window !== 'undefined' && (window.localStorage.getItem('accessToken') || window.sessionStorage.getItem('accessToken'))) || '',
                  refreshToken: (typeof window !== 'undefined' && (window.localStorage.getItem('refreshToken') || window.sessionStorage.getItem('refreshToken'))) || '',
                },
                isAuthenticated: true,
                _hasHydrated: true,
              });
            } else {
              if (typeof window !== 'undefined') {
                document.cookie = 'auth=; path=/; max-age=0; samesite=lax';
              }
              useAuthStore.setState({ isAuthenticated: false, user: null, tokens: null, _hasHydrated: true });
            }
          } else {
            useAuthStore.setState({ _hasHydrated: true });
          }
        };
      },
    }
  )
);
