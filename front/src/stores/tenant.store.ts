import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  displayName?: string;
  logo?: string;
  status: 'active' | 'inactive' | 'trial' | 'suspended';
  plan: string;
  role?: string;
  isDefault?: boolean;
}

interface TenantState {
  activeTenant: TenantInfo | null;
  availableTenants: TenantInfo[];
  _hasHydrated: boolean;

  setActiveTenant: (tenant: TenantInfo) => void;
  setAvailableTenants: (tenants: TenantInfo[]) => void;
  clearTenant: () => void;
  setHasHydrated: (v: boolean) => void;
}

/**
 * Tenant store — tracks which tenant/organization the user is currently viewing.
 * Persisted to localStorage so tenant selection survives refresh.
 */
export const useTenantStore = create<TenantState>()(
  persist(
    (set) => ({
      activeTenant: null,
      availableTenants: [],
      _hasHydrated: false,

      setHasHydrated: (v: boolean) => set({ _hasHydrated: v }),

      setActiveTenant: (tenant) => {
        if (typeof window !== 'undefined') {
          document.cookie = `activeTenant=${tenant.id}; path=/; samesite=lax; max-age=${60 * 60 * 24 * 30}`;
        }
        set({ activeTenant: tenant });
      },

      setAvailableTenants: (tenants) => {
        set({ availableTenants: tenants });
      },

      clearTenant: () => {
        if (typeof window !== 'undefined') {
          document.cookie = 'activeTenant=; path=/; max-age=0; samesite=lax';
        }
        set({ activeTenant: null, availableTenants: [] });
      },
    }),
    {
      name: 'tenant-storage',
      storage: createJSONStorage(() => {
        if (typeof window === 'undefined') return null as unknown as Storage;
        return window.localStorage;
      }),
      partialize: (state) => ({
        activeTenant: state.activeTenant,
        availableTenants: state.availableTenants,
      }),
      onRehydrateStorage: () => {
        return () => {
          useTenantStore.setState({ _hasHydrated: true });
        };
      },
    },
  ),
);
