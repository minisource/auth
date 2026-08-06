'use client';

import React from 'react';
import { ChevronsUpDown, Plus, Star, Building2, Loader2, Globe, Check } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Button,
  Badge,
  cn,
} from '@minisource/ui';
import { useMyTenants, ALL_TENANTS } from '@/hooks/use-my-tenants';
import type { TenantInfo } from '@/stores/tenant.store';
import { useAuthStore } from '@/stores';

interface TenantSelectorProps {
  /** Whether the sidebar is collapsed (icon-only mode) */
  collapsed?: boolean;
  /** Create tenant click handler (shown for admins) */
  onCreateTenant?: () => void;
  /** Custom class name */
  className?: string;
}

export function TenantSelector({
  collapsed,
  onCreateTenant,
  className,
}: TenantSelectorProps) {
  const { tenants, activeTenant, switchTenant, isLoading } = useMyTenants();
  const { isAdmin } = useAuthStore();
  const isSystemAdmin = isAdmin();

  const isGlobalActive = !activeTenant || activeTenant.id === 'all';

  if (isLoading) {
    return (
      <div className={cn('flex items-center justify-center py-2 border-b mb-3 pb-3', className)}>
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="mb-3 border-b pb-3 px-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            className={cn(
              'w-full justify-start gap-2.5 bg-background shadow-xs hover:bg-accent hover:text-accent-foreground transition-all border',
              collapsed ? 'h-10 w-10 p-0 mx-auto justify-center' : 'h-11 px-3 py-2',
              className,
            )}
          >
            <div
              className={cn(
                'flex items-center justify-center rounded-md shrink-0 size-7',
                isGlobalActive ? 'bg-primary/10 text-primary' : 'bg-secondary text-secondary-foreground',
              )}
            >
              {isGlobalActive ? <Globe className="size-4" /> : <Building2 className="size-4" />}
            </div>

            {!collapsed && (
              <>
                <div className="flex flex-col items-start min-w-0 flex-1 text-start">
                  <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider leading-none mb-1">
                    Organization Context
                  </span>
                  <span className="text-sm font-semibold truncate leading-none">
                    {activeTenant?.name ?? 'All Tenants (Global)'}
                  </span>
                </div>
                <ChevronsUpDown className="ml-auto size-4 shrink-0 text-muted-foreground/70" />
              </>
            )}
          </Button>
        </DropdownMenuTrigger>

        <DropdownMenuContent
          className="w-72 rounded-lg max-h-[min(70vh,28rem)] flex flex-col p-1.5 shadow-lg"
          align="start"
          side={collapsed ? 'right' : 'bottom'}
          sideOffset={6}
        >
          <DropdownMenuLabel className="text-xs font-semibold uppercase tracking-wider text-muted-foreground px-2 py-1.5">
            Switch Organization Context
          </DropdownMenuLabel>

          <div className="overflow-y-auto overflow-x-hidden min-h-0 space-y-0.5">
            {/* Global / All Tenants Option */}
            <DropdownMenuItem
              onClick={() => switchTenant(ALL_TENANTS)}
              className={cn(
                'flex items-center justify-between p-2 rounded-md cursor-pointer text-sm font-medium',
                isGlobalActive && 'bg-accent text-accent-foreground font-semibold',
              )}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary border border-primary/20">
                  <Globe className="size-4" />
                </div>
                <div className="flex flex-col min-w-0">
                  <span className="truncate">All Tenants (Global)</span>
                  <span className="text-xs text-muted-foreground font-normal">View system-wide data</span>
                </div>
              </div>
              {isGlobalActive && <Check className="size-4 text-primary shrink-0 ml-2" />}
            </DropdownMenuItem>

            <DropdownMenuSeparator className="my-1" />

            {/* List of Specific Tenants */}
            {tenants.map((tenant) => (
              <TenantItem
                key={tenant.id}
                tenant={tenant}
                isActive={activeTenant?.id === tenant.id}
                onSelect={() => switchTenant(tenant)}
              />
            ))}
          </div>

          {onCreateTenant && isSystemAdmin && (
            <>
              <DropdownMenuSeparator className="my-1" />
              <DropdownMenuItem
                onClick={onCreateTenant}
                className="cursor-pointer gap-2 p-2 rounded-md text-xs font-medium text-primary hover:text-primary focus:text-primary"
              >
                <Plus className="size-4" />
                Create New Tenant
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* TenantItem                                                                 */
/* -------------------------------------------------------------------------- */

function TenantItem({
  tenant,
  isActive,
  onSelect,
}: {
  tenant: TenantInfo;
  isActive: boolean;
  onSelect: () => void;
}) {
  return (
    <DropdownMenuItem
      onClick={onSelect}
      className={cn(
        'flex items-center justify-between p-2 rounded-md cursor-pointer text-sm font-medium',
        isActive && 'bg-accent text-accent-foreground font-semibold',
      )}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="flex size-7 shrink-0 items-center justify-center rounded-md border bg-muted/50">
          <Building2 className="size-4 text-muted-foreground" />
        </div>
        <div className="flex flex-col min-w-0">
          <span className="truncate">{tenant.name}</span>
          <span className="text-xs text-muted-foreground font-normal">Slug: {tenant.slug}</span>
        </div>
      </div>

      <div className="flex items-center gap-1.5 shrink-0 ml-2">
        {tenant.plan === 'enterprise' && (
          <Badge variant="blue" className="text-[10px] px-1.5 py-0">
            Enterprise
          </Badge>
        )}
        {tenant.isDefault && (
          <Star fill="#eab308" stroke="#eab308" className="size-3.5" />
        )}
        {isActive && <Check className="size-4 text-primary" />}
      </div>
    </DropdownMenuItem>
  );
}
