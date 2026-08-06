'use client';

import { useState } from 'react';
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, PageHeader } from '@minisource/ui';
import {
  Activity,
  Search,
  Loader2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  UserCircle,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
} from 'lucide-react';
import { useLoginLogs } from '@/hooks';
import { format } from 'date-fns';

type SortField = 'createdAt' | 'action' | 'ipAddress' | 'success';
type SortDir = 'asc' | 'desc';

export default function AdminLoginLogsPage() {
  const [actionFilter, setActionFilter] = useState('');
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<SortField>('createdAt');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const { data: logs, isLoading, error, refetch, isFetching } = useLoginLogs({
    action: actionFilter || undefined,
    search: search || undefined,
    orderBy: sortField,
    sort: sortDir,
    limit: 200,
  });

  const logList = Array.isArray(logs) ? logs : [];

  const formatAction = (action: string) => {
    return action.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
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
        title="Login Logs"
        description="Audit trail of login and authentication activity"
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        }
      />

      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by email, name, IP, or user agent..."
                className="pl-10"
                value={search}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearch(e.target.value)}
              />
            </div>
            <Select value={actionFilter} onValueChange={(v: string) => setActionFilter(v === ' ' ? '' : v)}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by action" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value=" ">All Actions</SelectItem>
                <SelectItem value="login">Login</SelectItem>
                <SelectItem value="login_failed">Failed Login</SelectItem>
                <SelectItem value="logout">Logout</SelectItem>
                <SelectItem value="password_reset">Password Reset</SelectItem>
                <SelectItem value="account_locked">Account Locked</SelectItem>
                <SelectItem value="otp_verify">OTP Verify</SelectItem>
                <SelectItem value="oauth_login">OAuth Login</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Activity Log</CardTitle>
          <CardDescription>Recent authentication events ({logList.length} results)</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('action')}
                >
                  Action <SortIcon field="action" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('success')}
                >
                  Status <SortIcon field="success" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('ipAddress')}
                >
                  IP Address <SortIcon field="ipAddress" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => toggleSort('createdAt')}
                >
                  Timestamp <SortIcon field="createdAt" />
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-12 text-center">
                    <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : error ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-12 text-center text-destructive">
                    Error loading logs: {(error as any)?.message || 'Unknown error'}
                  </TableCell>
                </TableRow>
              ) : logList.length > 0 ? (
                logList.map((log: any) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <UserCircle className="h-6 w-6 text-muted-foreground" />
                        <div>
                          <p className="text-sm font-medium">
                            {log.user_first_name || log.userEmail || log.user_email || 'Unknown'}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {log.user_email || '\u2014'}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium">
                        {formatAction(log.action)}
                      </span>
                    </TableCell>
                    <TableCell>
                      {log.success ? (
                        <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          Success
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-sm text-red-600 dark:text-red-400">
                          <XCircle className="h-3.5 w-3.5" />
                          Failed{log.error_msg ? `: ${log.error_msg}` : ''}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground font-mono">
                      {log.ip_address || log.ipAddress || '\u2014'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {log.created_at || log.createdAt ? format(new Date(log.created_at || log.createdAt), 'MMM d, yyyy HH:mm') : '\u2014'}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={5} className="py-16 text-center">
                    <Activity className="mx-auto mb-3 h-12 w-12 text-muted-foreground/40" />
                    <h3 className="mb-1 text-lg font-semibold">No Logs Found</h3>
                    <p className="text-sm text-muted-foreground">
                      {actionFilter || search ? 'No logs match the selected filter.' : 'No login activity recorded yet.'}
                    </p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
