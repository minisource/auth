'use client';

import { useState, useMemo } from 'react';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, PageHeader } from '@minisource/ui';
import {
  Activity,
  Loader2,
  RefreshCw,
  LogOut,
  Monitor,
  Smartphone,
  Globe,
  ChevronLeft,
  ChevronRight,
  Search,
  Users,
  Shield,
  Clock,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
} from 'lucide-react';
import {
  useAdminSessions,
  useAdminRevokeSession,
} from '@/hooks';
import { format } from 'date-fns';

type SortField = 'createdAt' | 'lastActiveAt' | 'ipAddress';
type SortDir = 'asc' | 'desc';
type StatusFilter = 'all' | 'active' | 'inactive';

export default function AdminSessionsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [sortField, setSortField] = useState<SortField>('createdAt');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const { data, isLoading, error, refetch, isFetching } = useAdminSessions({
    page,
    limit: 20,
    search: search || undefined,
    isActive: statusFilter === 'active' ? true : statusFilter === 'inactive' ? false : undefined,
    orderBy: sortField,
    sort: sortDir,
  });

  const { mutate: revokeSession, isPending: isRevoking } = useAdminRevokeSession();

  const sessions = data?.data ?? [];
  const meta = data?.meta;
  const totalPages = meta?.totalPages ?? 1;

  const stats = useMemo(() => {
    const total = meta?.total ?? 0;
    const uniqueUsers = new Set(sessions.map((s: any) => s.userId)).size;
    const active = sessions.filter((s: any) => s.isActive).length;
    const expired = sessions.filter((s: any) => s.expiresAt && new Date(s.expiresAt) < new Date()).length;
    return { total, active, expired, uniqueUsers };
  }, [sessions, meta]);

  const getDeviceIcon = (ua: string) => {
    if (!ua) return <Globe className="h-4 w-4" />;
    const lower = ua.toLowerCase();
    if (lower.includes('mobile') || lower.includes('iphone') || lower.includes('android')) {
      return <Smartphone className="h-4 w-4" />;
    }
    return <Monitor className="h-4 w-4" />;
  };

  const truncateUserAgent = (ua: string, max = 50) => {
    if (!ua) return 'Unknown';
    return ua.length > max ? ua.substring(0, max) + '...' : ua;
  };

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ArrowUpDown className="ml-1 h-3 w-3 opacity-50" />;
    return sortDir === 'asc' ? (
      <ArrowUp className="ml-1 h-3 w-3" />
    ) : (
      <ArrowDown className="ml-1 h-3 w-3" />
    );
  };

  return (
    <div className="container py-8">
      <PageHeader
        title="Sessions"
        description="View and manage all active user sessions"
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        }
      />

      {/* Analytics Cards */}
      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Sessions</p>
                <p className="text-2xl font-bold">{stats.total}</p>
              </div>
              <Activity className="h-8 w-8 text-muted-foreground/40" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active</p>
                <p className="text-2xl font-bold text-green-600">{stats.active}</p>
              </div>
              <Shield className="h-8 w-8 text-green-600/40" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Expired</p>
                <p className="text-2xl font-bold text-orange-600">{stats.expired}</p>
              </div>
              <Clock className="h-8 w-8 text-orange-600/40" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Unique Users</p>
                <p className="text-2xl font-bold">{stats.uniqueUsers}</p>
              </div>
              <Users className="h-8 w-8 text-muted-foreground/40" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search & Filters */}
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by email, name, IP, or user agent..."
                className="pl-10"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v as StatusFilter); setPage(1); }}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Sessions Table */}
      <Card>
        <CardHeader>
          <CardTitle>All Sessions</CardTitle>
          <CardDescription>{meta?.total ?? 0} total sessions found</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Device</TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('ipAddress')}
                >
                  IP Address <SortIcon field="ipAddress" />
                </TableHead>
                <TableHead>Status</TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('lastActiveAt')}
                >
                  Last Active <SortIcon field="lastActiveAt" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('createdAt')}
                >
                  Created <SortIcon field="createdAt" />
                </TableHead>
                <TableHead className="w-[80px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="py-12 text-center">
                    <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : error ? (
                <TableRow>
                  <TableCell colSpan={7} className="py-12 text-center text-destructive">
                    <p>Error loading sessions: {(error as any)?.message || 'Unknown error'}</p>
                  </TableCell>
                </TableRow>
              ) : sessions.length > 0 ? (
                sessions.map((session: any) => (
                  <TableRow key={session.id}>
                    <TableCell>
                      <div>
                        <p className="text-sm font-medium">
                          {session.userFirstName} {session.userLastName}
                        </p>
                        <p className="text-xs text-muted-foreground">{session.userEmail}</p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {getDeviceIcon(session.userAgent)}
                        <span className="text-xs text-muted-foreground" title={session.userAgent}>
                          {truncateUserAgent(session.userAgent)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {session.ipAddress || '\u2014'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={session.isActive ? 'default' : 'secondary'}>
                        {session.isActive ? 'Active' : 'Revoked'}
                      </Badge>
                      {session.expiresAt && new Date(session.expiresAt) < new Date() && (
                        <Badge variant="outline" className="ml-1">
                          Expired
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {session.lastActiveAt
                        ? format(new Date(session.lastActiveAt), 'MMM d, HH:mm')
                        : '\u2014'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {format(new Date(session.createdAt), 'MMM d, yyyy')}
                    </TableCell>
                    <TableCell>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive"
                            disabled={!session.isActive}
                            title="Revoke Session"
                          >
                            <LogOut className="h-4 w-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Revoke Session</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will force logout {session.userFirstName} {session.userLastName}. They will need to re-authenticate.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => revokeSession(session.id)}
                              className="bg-destructive text-destructive-foreground"
                              disabled={isRevoking}
                            >
                              {isRevoking && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                              Revoke
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="py-16 text-center">
                    <Activity className="mx-auto mb-3 h-12 w-12 text-muted-foreground/40" />
                    <h3 className="mb-1 text-lg font-semibold">No Sessions Found</h3>
                    <p className="text-sm text-muted-foreground">
                      {search || statusFilter !== 'all'
                        ? 'No sessions match your filters.'
                        : 'There are no sessions in the system.'}
                    </p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {meta && totalPages > 1 && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Page {meta.page} of {totalPages} ({meta.total} total)
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
