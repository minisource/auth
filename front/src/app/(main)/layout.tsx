'use client';

import React, { useMemo } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuthStore } from '@/stores';
import { useLogout } from '@/hooks';
import { useLang, useT } from '@/shared/i18n/LanguageProvider';
import {
  SidebarProvider,
  Sidebar,
  SidebarTrigger,
  Topbar,
  Footer,
  UserMenu,
  SidebarInset,
} from '@minisource/app-shell';
import {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
  ServerTime,
  Separator,
} from '@minisource/ui';
import { HeaderControls } from '@/components/layout/header-controls';
import { TenantSelector } from '@/components/layout/tenant-selector';
import { AuthGuard } from '@/components/shared/AuthGuard';
import {
  LayoutDashboard,
  Users,
  Shield,
  Key,
  Server,
  Building2,
  UserCircle,
  LogOut,
  Activity,
  Wrench,
  Link2,
  Settings,
} from 'lucide-react';

/* -------------------------------------------------------------------------- */
/* Navigation Items                                                           */
/* -------------------------------------------------------------------------- */

const useNavItems = () => {
  const { t } = useT();
  return [
    { id: 'dashboard', label: t('nav.dashboard'), href: '/dashboard', icon: LayoutDashboard },
    {
      id: 'identity',
      label: t('nav.identity'),
      href: '#',
      icon: Users,
      children: [
        { id: 'users', label: t('nav.users'), href: '/admin/users', icon: Users },
        { id: 'sessions', label: t('nav.sessions'), href: '/admin/sessions', icon: Activity },
      ],
    },
    {
      id: 'access',
      label: t('nav.accessControl'),
      href: '#',
      icon: Shield,
      children: [
        { id: 'roles', label: t('nav.roles'), href: '/admin/roles', icon: Shield },
        { id: 'permissions', label: t('nav.permissions'), href: '/admin/permissions', icon: Key },
      ],
    },
    {
      id: 'tenancy',
      label: t('nav.tenancy'),
      href: '#',
      icon: Building2,
      children: [
        { id: 'tenants', label: t('nav.tenants'), href: '/admin/tenants', icon: Building2 },
      ],
    },
    {
      id: 'integrations',
      label: t('nav.integrations'),
      href: '#',
      icon: Server,
      children: [
        { id: 'oauth', label: t('nav.oauthProviders'), href: '/admin/oauth-providers', icon: Link2 },
        { id: 'service-clients', label: t('nav.serviceClients'), href: '/admin/service-clients', icon: Server },
      ],
    },
    {
      id: 'tools',
      label: t('nav.tools'),
      href: '#',
      icon: Wrench,
      children: [
        { id: 'settings', label: t('nav.settings'), href: '/admin/settings', icon: Settings },
        { id: 'login-logs', label: t('nav.loginLogs'), href: '/admin/login-logs', icon: Activity },
        { id: 'api-lab', label: t('nav.apiLab'), href: '/admin/api-lab', icon: Wrench },
        { id: 'token-tools', label: t('nav.tokenTools'), href: '/admin/tools/validate-token', icon: Key },
        { id: 'service-auth', label: t('nav.serviceAuth'), href: '/admin/tools/service-auth', icon: Server },
      ],
    },
    { id: 'profile', label: t('nav.profile'), href: '/profile', icon: UserCircle },
  ];
};

/* -------------------------------------------------------------------------- */
/* Breadcrumb Generator                                                       */
/* -------------------------------------------------------------------------- */

interface BreadcrumbItem {
  label: string;
  href?: string;
}

function generateBreadcrumbs(pathname: string, t: (key: string) => string): BreadcrumbItem[] {
  if (pathname === '/' || pathname === '/dashboard') {
    return [{ label: t('nav.dashboard') }];
  }

  const segments = pathname.split('/').filter(Boolean);
  const crumbs: BreadcrumbItem[] = [{ label: t('nav.dashboard'), href: '/dashboard' }];

  const labelMap: Record<string, string> = {
    admin: 'Admin',
    users: t('nav.users'),
    roles: t('nav.roles'),
    permissions: t('nav.permissions'),
    tenants: t('nav.tenants'),
    sessions: t('nav.sessions'),
    settings: t('nav.settings'),
    profile: t('nav.profile'),
    'login-logs': t('nav.loginLogs'),
    'oauth-providers': t('nav.oauthProviders'),
    'service-clients': t('nav.serviceClients'),
    tools: t('nav.tools'),
    'api-lab': t('nav.apiLab'),
    'validate-token': t('nav.tokenTools'),
    'service-auth': t('nav.serviceAuth'),
  };

  let path = '';
  for (const seg of segments) {
    if (seg === 'dashboard') continue;
    path += `/${seg}`;
    crumbs.push({
      label: labelMap[seg] || seg.charAt(0).toUpperCase() + seg.slice(1),
      href: path,
    });
  }

  return crumbs;
}

/* -------------------------------------------------------------------------- */
/* MainLayout                                                                 */
/* -------------------------------------------------------------------------- */

export default function MainLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user } = useAuthStore();
  const { mutate: logout } = useLogout();
  const { lang } = useLang();
  const { t } = useT();
  const navItems = useNavItems();
  const dir = lang === 'fa' ? 'rtl' : 'ltr';

  const userMenuItems = [
    { id: 'profile', label: t('nav.profile'), icon: UserCircle, href: '/profile' },
    { id: 'separator', label: '', separator: true },
    { id: 'logout', label: t('nav.logout'), icon: LogOut, onClick: () => logout(), destructive: true },
  ];

  const initials = user
    ? `${user.firstName?.[0] || ''}${user.lastName?.[0] || ''}`.toUpperCase() || user.email?.[0]?.toUpperCase() || '?'
    : '?';

  const breadcrumbs = useMemo(() => generateBreadcrumbs(pathname, t), [pathname, t]);
  const serverTimeISO = useMemo(() => new Date().toISOString(), []);

  return (
    <AuthGuard>
      <SidebarProvider defaultOpen dir={dir}>
        {/* Brand + Tenant Selector + Navigation */}
        <Sidebar
          items={navItems}
          activeHref={pathname}
          linkComponent={Link}
          brand={
            <div className="w-full space-y-2.5">
              {/* Logo + Title */}
              <Link href="/dashboard" className="flex items-center gap-2 px-1 pt-1">
                <span className="text-xl font-bold">⚡</span>
                <span className="text-lg font-bold tracking-tight group-data-[collapsible=icon]:hidden">
                  MiniSource
                </span>
              </Link>
              {/* Tenant Selector */}
              <TenantSelector />
            </div>
          }
          footer={
            <div className="px-2 py-1 text-xs font-medium text-muted-foreground group-data-[collapsible=icon]:hidden truncate">
              {user?.email ?? ''}
            </div>
          }
        />

        <SidebarInset
          dir={dir}
          topbar={
            <Topbar
              left={
                <div className="flex items-center gap-2">
                  <SidebarTrigger />
                  <Separator orientation="vertical" className="mr-2 h-4" />
                  {/* Breadcrumb */}
                  <Breadcrumb className="hidden sm:block">
                    <BreadcrumbList>
                      {breadcrumbs.map((crumb, i) => (
                        <React.Fragment key={crumb.label}>
                          <BreadcrumbItem>
                            {i < breadcrumbs.length - 1 ? (
                              <BreadcrumbLink asChild>
                                <Link href={crumb.href!}>
                                  {crumb.label}
                                </Link>
                              </BreadcrumbLink>
                            ) : (
                              <BreadcrumbPage>{crumb.label}</BreadcrumbPage>
                            )}
                          </BreadcrumbItem>
                          {i < breadcrumbs.length - 1 && <BreadcrumbSeparator />}
                        </React.Fragment>
                      ))}
                    </BreadcrumbList>
                  </Breadcrumb>
                </div>
              }
              right={
                <div className="flex items-center gap-1.5 sm:gap-2">
                  <div className="hidden lg:block">
                    <ServerTime
                      serverTime={serverTimeISO}
                      timezone={Intl.DateTimeFormat().resolvedOptions().timeZone}
                    />
                  </div>
                  <HeaderControls />
                  <UserMenu
                    name={user ? `${user.firstName || ''} ${user.lastName || ''}`.trim() : undefined}
                    email={user?.email}
                    initials={initials}
                    items={userMenuItems}
                    dir={dir}
                  />
                </div>
              }
              dir={dir}
            />
          }
          footer={
            <Footer dir={dir}>
              © {new Date().getFullYear()} MiniSource. All rights reserved.
            </Footer>
          }
        >
          <div className="p-6">{children}</div>
        </SidebarInset>
      </SidebarProvider>
    </AuthGuard>
  );
}
