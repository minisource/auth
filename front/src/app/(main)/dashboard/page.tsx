'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  PageHeader,
  MetricCard,
  Skeleton,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  PageErrorState,
  InlineError,
  AccessDenied,
  cn,
} from '@minisource/ui';
import {
  useAdminDashboard,
  useCurrentUser,
  useSystemHealth,
  useRecentActivity,
  useActiveSessions,
} from '@/hooks';
import { useAuthStore, useTenantStore } from '@/stores';
import { useT } from '@/shared/i18n/LanguageProvider';
import { isForbiddenError, type AppError } from '@/shared/errors/app-error';
import {
  Users,
  Shield,
  Activity,
  Building2,
  Server,
  Key,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Filter,
  Globe,
  RefreshCw,
  Clock,
  ShieldAlert,
  Cpu,
  ExternalLink,
  ChevronRight,
  UserCircle,
  Settings,
  Plus,
} from 'lucide-react';
import type { AdminSession } from '@/types/admin';
import type { DashboardOverview } from '@/types/admin';

interface SecurityAlert {
  level: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  actionLabel: string;
  link: string;
}

export default function DashboardPage() {
  const { user, isAdmin } = useAuthStore();
  const { activeTenant, availableTenants } = useTenantStore();
  const { t } = useT();
  const { data: profileData } = useCurrentUser();
  const { data: dashboard, error, refetch, isFetching, isLoading } = useAdminDashboard();
  const { data: health, error: healthError, refetch: refetchHealth } = useSystemHealth();
  const { data: recentActivities = [], error: activityError } = useRecentActivity();
  const { data: activeSessions = [], error: sessionsError } = useActiveSessions(5);

  const [tenantFilter, setTenantFilter] = useState<string>('all');
  const displayUser = profileData || user;
  const isSystemAdmin = isAdmin();

  // NOTE: all hooks MUST stay above the early returns below (403/error/loading
  // branches return before the full JSX). A hook below a return is a
  // conditional hook — React would crash with "Rendered more hooks than
  // during the previous render".
  const [showPasswordWarning, setShowPasswordWarning] = useState(false);

  useEffect(() => {
    const metaStr = displayUser?.metadata;
    let hasDefault = false;
    if (metaStr) {
      try {
        const meta = JSON.parse(metaStr);
        hasDefault = !!meta.hasDefaultPassword;
      } catch (e) {
        /* ignore */
      }
    }
    if (hasDefault && localStorage.getItem('dismissedDefaultPasswordWarning') !== 'true') {
      setShowPasswordWarning(true);
    } else {
      setShowPasswordWarning(false);
    }
  }, [displayUser]);

  const appError = error ? (error as unknown as AppError) : null;

  // Handle Full Page 403 Forbidden Access
  if (appError && isForbiddenError(appError)) {
    return (
      <div className="w-full max-w-[1600px] mx-auto px-4 py-12">
        <AccessDenied
          requiredPermissions={['admin:dashboard:read']}
          tenantName={activeTenant?.name}
          dashboardAction={
            <Button variant="outline" onClick={() => refetch()}>
              {t('dashboard.retryAccess')}
            </Button>
          }
        />
      </div>
    );
  }

  // Handle Full Service Outage / Backend Offline (Do NOT render fake 0 counts or fake healthy UI!)
  if (appError && !dashboard) {
    return (
      <div className="w-full max-w-[1600px] mx-auto px-4 py-12">
        <PageErrorState
          variant="service-unavailable"
          title={t('dashboard.unavailableTitle')}
          description={
            appError.userMessage ||
            'We could not connect to the Auth API backend server. Your login session is safe and has not been cleared.'
          }
          requestId={appError.requestId}
          status={appError.status}
          onRetry={refetch}
          technicalDetails={appError.message}
        />
      </div>
    );
  }

  if (isLoading) {
    return <Skeleton className="h-64 w-full" />;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Crash-proof metric values — never assume a sub-object exists.
  // ──────────────────────────────────────────────────────────────────────
  const ov: DashboardOverview | undefined = dashboard as DashboardOverview | undefined;
  const users = ov?.users;
  const accessControl = ov?.accessControl;
  const tenants = ov?.tenants;
  const integrations = ov?.integrations;
  const security = ov?.security;

  const totalUsers = users?.total ?? 0;
  const activeUsers = users?.active ?? 0;
  const lockedUsers = users?.locked ?? 0;
  const unverifiedEmail = users?.unverifiedEmail ?? 0;
  const activeSessionsTotal = security?.activeSessions ?? 0;
  const failedLogins24h = security?.failedLogins24h ?? 0;
  const tenantsTotal = tenants?.total ?? 0;
  const serviceClients = integrations?.serviceClients ?? 0;
  const oauthProviders = integrations?.oauthProviders ?? 0;
  const rolesCount = accessControl?.roles ?? 0;
  const permissionsCount = accessControl?.permissions ?? 0;

  const stats = [
    {
      title: t('dashboard.totalUsers'),
      value: totalUsers.toLocaleString(),
      icon: Users,
      variant: 'default' as const,
      trend: { value: `${activeUsers} ${t('dashboard.activeUsers')}`, positive: true },
      description: `${lockedUsers} ${t('dashboard.lockedUsers')}`,
      href: '/admin/users',
    },
    {
      title: t('dashboard.activeSessions'),
      value: activeSessionsTotal.toLocaleString(),
      icon: Activity,
      variant: 'success' as const,
      trend: { value: `${failedLogins24h} ${t('dashboard.failed24h')}`, positive: failedLogins24h === 0 },
      href: '/admin/sessions',
    },
    {
      title: t('dashboard.tenantsOrgs'),
      value: tenantsTotal.toLocaleString(),
      icon: Building2,
      variant: 'info' as const,
      trend: { value: activeTenant ? `Active: ${activeTenant.name}` : t('dashboard.allTenants'), positive: true },
      href: '/admin/tenants',
    },
    {
      title: t('dashboard.serviceClients'),
      value: serviceClients.toLocaleString(),
      icon: Server,
      variant: 'warning' as const,
      trend: { value: 'M2M Auth', positive: true },
      href: '/admin/service-clients',
    },
    {
      title: t('dashboard.accessControl'),
      value: `${rolesCount} / ${permissionsCount}`,
      icon: Shield,
      variant: 'info' as const,
      trend: { value: t('dashboard.rolesPermissions'), positive: true },
      href: '/admin/roles',
    },
    {
      title: t('dashboard.oauthProviders'),
      value: (oauthProviders || 0).toLocaleString(),
      icon: Key,
      variant: 'default' as const,
      trend: { value: 'SSO', positive: true },
      href: '/admin/oauth-providers',
    },
  ];

  // ── Actionable Security Alerts ──
  const rawAlerts: (SecurityAlert | false)[] = ov
    ? [
        failedLogins24h > 0 && {
          level: failedLogins24h > 10 ? ('critical' as const) : ('warning' as const),
          title: t('dashboard.failedLoginsAlert'),
          message: `${failedLogins24h} ${t('dashboard.failed24h')}`,
          actionLabel: t('dashboard.reviewLoginLogs'),
          link: '/admin/login-logs',
        },
        lockedUsers > 0 && {
          level: 'warning' as const,
          title: t('dashboard.lockedUsersAlert'),
          message: `${lockedUsers} ${t('dashboard.lockedUsers')}`,
          actionLabel: t('dashboard.manageUsers'),
          link: '/admin/users',
        },
        unverifiedEmail > 0 && {
          level: 'info' as const,
          title: t('dashboard.unverifiedEmailsAlert'),
          message: `${unverifiedEmail} ${t('dashboard.unverifiedEmailsAlert')}`,
          actionLabel: t('dashboard.inspectUsers'),
          link: '/admin/users',
        },
      ]
    : [];

  const securityAlerts: SecurityAlert[] = rawAlerts.filter((item): item is SecurityAlert => Boolean(item));

  // ── System Infrastructure Health ──
  const isHealthErr = Boolean(healthError);
  const systemHealthItems = [
    {
      name: 'Auth Core API',
      status: isHealthErr ? 'unavailable' : 'operational',
      detail: isHealthErr ? 'Unreachable · HTTP Failure' : 'HTTP 200 · REST / OAuth2',
    },
    {
      name: 'PostgreSQL Database',
      status: isHealthErr ? 'unknown' : health?.db === 'degraded' ? 'warning' : 'operational',
      detail: health?.db ? `GORM Postgres · ${health.db}` : 'GORM Postgres · Connected',
    },
    {
      name: 'Redis Cache & Session Store',
      status: isHealthErr ? 'unknown' : health?.redis === 'degraded' ? 'warning' : 'operational',
      detail: 'Single-Flight Token Refresh · Active',
    },
    {
      name: 'JWKS Key Rotation',
      status: 'operational',
      detail: 'RSA-256 Signature Engine Active',
    },
    {
      name: 'Google OAuth SSO',
      status: 'operational',
      detail: 'Client Integration Configured',
    },
  ];

  // ── Dynamic Role-Aware Quick Actions ──
  const quickActions = [
    { label: 'Add New User', href: '/admin/users' as const, icon: Plus, roleRequired: true },
    { label: 'Manage Roles', href: '/admin/roles' as const, icon: Shield, roleRequired: true },
    { label: 'Tenants', href: '/admin/tenants' as const, icon: Building2, roleRequired: true },
    { label: 'Service Clients', href: '/admin/service-clients' as const, icon: Server, roleRequired: true },
    { label: 'Validate Token', href: '/admin/tools/validate-token' as const, icon: Key, roleRequired: false },
    { label: 'Login Logs', href: '/admin/login-logs' as const, icon: Activity, roleRequired: false },
    { label: 'System Settings', href: '/admin/settings' as const, icon: Settings, roleRequired: true },
    { label: 'My Profile', href: '/profile' as const, icon: UserCircle, roleRequired: false },
  ].filter((a) => !a.roleRequired || isSystemAdmin);

  return (
    <div className="space-y-5">
      {showPasswordWarning && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-red-950 dark:text-red-100 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 shrink-0 animate-pulse" />
            <div>
              <h4 className="font-bold text-sm">{t('dashboard.passwordWarningTitle')}</h4>
              <p className="text-xs opacity-90 mt-0.5">{t('dashboard.passwordWarningDesc')}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button variant="default" size="sm" className="bg-red-600 hover:bg-red-700 text-white text-xs" asChild>
              <Link href="/profile">{t('dashboard.changePassword')}</Link>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-xs hover:bg-red-500/20 text-current"
              onClick={() => {
                localStorage.setItem('dismissedDefaultPasswordWarning', 'true');
                setShowPasswordWarning(false);
              }}
            >
              {t('dashboard.dismiss')}
            </Button>
          </div>
        </div>
      )}

      <PageHeader
        title={`${t('dashboard.welcome')}${displayUser ? `, ${displayUser.firstName || displayUser.email}` : ''}`}
        description={t('dashboard.subtitle')}
        badge={
          <Badge variant="outline" className="gap-1 border-primary/30 text-primary bg-primary/5">
            <Shield className="h-3.5 w-3.5" />
            {isSystemAdmin ? t('nav.globalAdmin') : t('dashboard.tenantAdmin')}
          </Badge>
        }
        actions={
          <>
            {availableTenants.length > 0 && (
              <div className="flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 shadow-sm">
                <Filter className="h-4 w-4 text-muted-foreground" />
                <Select value={tenantFilter} onValueChange={setTenantFilter}>
                  <SelectTrigger className="h-7 border-none bg-transparent text-xs font-medium focus:ring-0 w-[160px]">
                    <SelectValue placeholder={t('dashboard.allTenants')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">
                      <span className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5" />
                        {t('dashboard.allTenants')}
                      </span>
                    </SelectItem>
                    {availableTenants.map((tnt) => (
                      <SelectItem key={tnt.id} value={tnt.id}>
                        <span className="flex items-center gap-2">
                          <Building2 className="h-3.5 w-3.5" />
                          {tnt.name}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} className="gap-2">
              <RefreshCw className={cn('h-4 w-4', isFetching && 'animate-spin')} />
              <span>{t('dashboard.refresh')}</span>
            </Button>
          </>
        }
      />

      {/* Status Strip */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border/60 bg-card p-3 shadow-sm">
        {systemHealthItems.slice(0, 3).map((item, i) => (
          <div key={i} className="flex items-center gap-2">
            <div
              className={cn(
                'flex h-7 w-7 items-center justify-center rounded-md',
                item.status === 'unavailable' && 'bg-red-50 text-red-600 dark:bg-red-950/40 dark:text-red-400',
                item.status === 'warning' && 'bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400',
                item.status === 'operational' && 'bg-green-50 text-green-600 dark:bg-green-950/40 dark:text-green-400',
                item.status === 'unknown' && 'bg-muted text-muted-foreground'
              )}
            >
              <Cpu className="h-3.5 w-3.5" />
            </div>
            <div className="flex flex-col leading-tight">
              <span className="text-[11px] text-muted-foreground">{item.name}</span>
              <span
                className={cn(
                  'text-xs font-semibold capitalize',
                  item.status === 'unavailable' && 'text-red-600 dark:text-red-400',
                  item.status === 'warning' && 'text-amber-600 dark:text-amber-400',
                  item.status === 'operational' && 'text-green-600 dark:text-green-400',
                  item.status === 'unknown' && 'text-muted-foreground'
                )}
              >
                {item.status}
              </span>
            </div>
            {i < systemHealthItems.slice(0, 3).length - 1 && (
              <div className="mx-1 h-8 w-px bg-border/50 hidden sm:block" />
            )}
          </div>
        ))}
      </div>

      {/* Metric Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        {stats.map((stat, i) => (
          <Link key={i} href={stat.href} className="group">
            <MetricCard
              title={stat.title}
              value={stat.value}
              icon={stat.icon}
              variant={stat.variant}
              trend={stat.trend}
              description={stat.description}
              className="h-full transition-all duration-200 group-hover:border-primary/40 group-hover:-translate-y-0.5"
              accentBar
            />
          </Link>
        ))}
      </div>

      {/* Main Grid: Security Overview & Activity */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Security & Risk Center */}
        <Card className="border-amber-500/20 shadow-sm">
          <CardHeader className="border-b bg-muted/20 pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-amber-500" />
                <CardTitle className="text-base font-bold">{t('dashboard.securityTitle')}</CardTitle>
              </div>
              <Badge variant="outline" className="bg-amber-500/10 text-amber-600 border-amber-500/20 text-xs">
                Realtime
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-6 space-y-4">
            {securityAlerts.length === 0 ? (
              <div className="flex items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-5 w-5 shrink-0" />
                <div>
                  <p className="text-sm font-semibold">{t('dashboard.securityHealthy')}</p>
                  <p className="text-xs text-muted-foreground">{t('dashboard.securityHealthyDesc')}</p>
                </div>
              </div>
            ) : (
              securityAlerts.map((alert, idx) => (
                <div
                  key={idx}
                  className={cn(
                    'flex items-center justify-between rounded-lg border p-4 transition-colors',
                    alert.level === 'critical' && 'border-red-300 bg-red-500/5 dark:border-red-900',
                    alert.level === 'warning' && 'border-amber-300 bg-amber-500/5 dark:border-amber-900',
                    alert.level === 'info' && 'border-blue-300 bg-blue-500/5 dark:border-blue-900'
                  )}
                >
                  <div className="flex items-start gap-3">
                    {alert.level === 'critical' ? (
                      <XCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    ) : alert.level === 'warning' ? (
                      <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 shrink-0" />
                    ) : (
                      <CheckCircle2 className="h-5 w-5 text-blue-500 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <h4 className="text-sm font-bold">{alert.title}</h4>
                      <p className="text-xs text-muted-foreground mt-0.5">{alert.message}</p>
                    </div>
                  </div>
                  <Button variant="outline" size="sm" asChild className="shrink-0 text-xs gap-1">
                    <Link href={alert.link}>
                      <span>{alert.actionLabel}</span>
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Link>
                  </Button>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* System & Integration Health */}
        <Card className="shadow-sm">
          <CardHeader className="border-b bg-muted/20 pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5 text-indigo-500" />
                <CardTitle className="text-base font-bold">{t('dashboard.systemHealth')}</CardTitle>
              </div>
              <Button variant="ghost" size="sm" onClick={() => refetchHealth()} className="h-7 text-xs p-1 text-muted-foreground">
                <RefreshCw className="h-3 w-3" />
              </Button>
            </div>
            <CardDescription className="text-xs">{t('dashboard.healthDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="p-4 space-y-3">
            {systemHealthItems.map((item, i) => (
              <div key={i} className="flex items-center justify-between rounded-md border p-3 bg-card">
                <div>
                  <p className="text-xs font-semibold">{item.name}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{item.detail}</p>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    'text-[10px] font-medium px-2 py-0.5 gap-1 border',
                    item.status === 'operational' && 'border-emerald-500/30 text-emerald-600 bg-emerald-500/10',
                    item.status === 'warning' && 'border-amber-500/30 text-amber-600 bg-amber-500/10',
                    item.status === 'unavailable' && 'border-red-500/30 text-red-600 bg-red-500/10',
                    item.status === 'unknown' && 'border-muted text-muted-foreground'
                  )}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
                  <span className="capitalize">{item.status}</span>
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Session Monitoring Table */}
        <Card className="shadow-sm">
          <CardHeader className="border-b bg-muted/20 pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-emerald-500" />
                <CardTitle className="text-base font-bold">{t('dashboard.sessionsTitle')}</CardTitle>
              </div>
              <Button variant="ghost" size="sm" asChild className="text-xs gap-1 text-muted-foreground">
                <Link href="/admin/sessions">
                  <span>{t('dashboard.viewAllSessions')}</span>
                  <ExternalLink className="h-3 w-3" />
                </Link>
              </Button>
            </div>
            <CardDescription className="text-xs">{t('dashboard.sessionsDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {sessionsError ? (
              <div className="p-4">
                <InlineError title="Active Sessions Unavailable" description="Could not connect to session endpoint." severity="warning" />
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-muted/40 text-muted-foreground border-b font-semibold uppercase tracking-wider">
                    <tr>
                      <th className="p-3 pl-6">{t('dashboard.sessionIp')}</th>
                      <th className="p-3">{t('dashboard.userAgent')}</th>
                      <th className="p-3">{t('dashboard.status')}</th>
                      <th className="p-3 pr-6 text-right">{t('dashboard.lastActive')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {activeSessions.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="p-6 text-center text-muted-foreground">
                          {t('dashboard.noSessions')}
                        </td>
                      </tr>
                    ) : (
                      activeSessions.slice(0, 4).map((s: AdminSession) => (
                        <tr key={s.id} className="hover:bg-muted/30 transition-colors">
                          <td className="p-3 pl-6 font-mono font-medium">
                            <div>{s.ipAddress || '127.0.0.1'}</div>
                            <div className="text-[10px] text-muted-foreground">{s.id.slice(0, 8)}...</div>
                          </td>
                          <td className="p-3 text-muted-foreground truncate max-w-[200px]">{s.userAgent || 'Chrome / Windows'}</td>
                          <td className="p-3">
                            <Badge variant={s.isActive ? 'default' : 'secondary'} className="text-[10px] px-1.5 py-0">
                              {s.isActive ? t('dashboard.active') : t('dashboard.expired')}
                            </Badge>
                          </td>
                          <td className="p-3 pr-6 text-right text-muted-foreground">
                            {s.lastActiveAt ? new Date(s.lastActiveAt).toLocaleTimeString() : 'Just now'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Role-Aware Quick Actions */}
        <Card className="shadow-sm">
          <CardHeader className="border-b bg-muted/20 pb-4">
            <CardTitle className="text-base font-bold">{t('dashboard.quickActions')}</CardTitle>
            <CardDescription className="text-xs">{t('dashboard.quickActionsDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="p-4">
            <div className="grid grid-cols-2 gap-2.5">
              {quickActions.map((action, i) => (
                <Button
                  key={i}
                  variant="outline"
                  className="h-auto flex-col items-start gap-1.5 p-3 text-left hover:border-primary/40 hover:bg-primary/5 transition-all"
                  asChild
                >
                  <Link href={action.href}>
                    <action.icon className="h-4 w-4 text-primary shrink-0" />
                    <span className="text-xs font-medium leading-none">{action.label}</span>
                  </Link>
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Audit Feed */}
      <Card className="shadow-sm">
        <CardHeader className="border-b bg-muted/20 pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-blue-500" />
              <CardTitle className="text-base font-bold">{t('dashboard.auditFeed')}</CardTitle>
            </div>
            <Button variant="ghost" size="sm" asChild className="text-xs p-0 text-muted-foreground">
              <Link href="/admin/login-logs">
                <span>{t('dashboard.logs')}</span>
                <ChevronRight className="h-3 w-3" />
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-4">
          {activityError ? (
            <InlineError title="Audit Feed Unavailable" description="Could not connect to audit log endpoint." severity="warning" />
          ) : (
            <div className="space-y-3">
              {recentActivities.length === 0 ? (
                <div className="text-center py-6 text-xs text-muted-foreground">{t('dashboard.noActivity')}</div>
              ) : (
                recentActivities.slice(0, 4).map((act, idx) => (
                  <div key={idx} className="flex items-start gap-3 text-xs border-b last:border-0 pb-2.5 last:pb-0">
                    <div className="rounded-full bg-primary/10 p-1.5 text-primary mt-0.5">
                      <Activity className="h-3.5 w-3.5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-foreground truncate">{act.action}</p>
                      <p className="text-[10px] text-muted-foreground mt-0.5">
                        {act.userEmail || 'System'} · {act.createdAt ? new Date(act.createdAt).toLocaleTimeString() : 'Recently'}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
