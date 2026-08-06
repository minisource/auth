import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { useTenantStore, type TenantInfo } from '@/stores/tenant.store';
import { useAuthStore } from '@/stores/auth.store';
import { QUERY_KEYS } from '@/config/constants';
import { useEffect } from 'react';

export const ALL_TENANTS: TenantInfo = {
  id: 'all',
  name: 'All Tenants (Global)',
  slug: 'all',
  status: 'active',
  plan: 'global',
};

/**
 * Fetches tenants that the current user belongs to.
 * Defaults to "All Tenants (Global)" if no tenant is selected.
 */
export function useMyTenants() {
  const { isAuthenticated } = useAuthStore();
  const { activeTenant, availableTenants, setActiveTenant, setAvailableTenants } =
    useTenantStore();

  const query = useQuery<TenantInfo[]>({
    queryKey: QUERY_KEYS.auth.myTenants(),
    queryFn: () => api.get<TenantInfo[]>('/users/me/tenants'),
    enabled: isAuthenticated,
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
    retry: false,
  });

  // Sync available tenants to store & default to ALL_TENANTS
  useEffect(() => {
    if (query.data) {
      setAvailableTenants(query.data);

      // Default to "All Tenants" if no tenant is currently set
      if (!activeTenant) {
        setActiveTenant(ALL_TENANTS);
      }
    }
  }, [query.data, activeTenant, setActiveTenant, setAvailableTenants]);

  const switchTenant = (tenant: TenantInfo) => {
    setActiveTenant(tenant);
    // Reload page to re-fetch all tenant-scoped API queries seamlessly
    if (typeof window !== 'undefined') {
      window.location.reload();
    }
  };

  return {
    tenants: availableTenants,
    activeTenant: activeTenant || ALL_TENANTS,
    switchTenant,
    isLoading: query.isLoading,
    error: query.error,
  };
}
