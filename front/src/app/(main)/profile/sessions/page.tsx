'use client';

import { useState } from 'react';
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from '@minisource/ui';
import { useUserSessions, useLogout } from '@/hooks';
import { format } from 'date-fns';
import {
  Smartphone,
  Laptop,
  Globe,
  Loader2,
  LogOut,
  Shield,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

const ITEMS_PER_PAGE = 5;

function getDeviceIcon(ua: string) {
  if (/mobile|android|iphone|ipad/i.test(ua)) return Smartphone;
  if (/windows|mac|linux/i.test(ua)) return Laptop;
  return Globe;
}

function getDeviceName(ua: string) {
  if (/mobile|android/i.test(ua)) return 'Mobile';
  if (/iphone|ipad/i.test(ua)) return 'iOS';
  if (/windows/i.test(ua)) return 'Windows';
  if (/mac/i.test(ua)) return 'macOS';
  if (/linux/i.test(ua)) return 'Linux';
  return 'Unknown Device';
}

export default function SessionsPage() {
  const [page, setPage] = useState(1);
  const { data: sessions, isLoading, refetch } = useUserSessions();
  const { mutate: logout, isPending: isLoggingOut } = useLogout();

  const sessionList = sessions ?? [];
  const totalPages = Math.ceil(sessionList.length / ITEMS_PER_PAGE);
  const paginatedSessions = sessionList.slice(
    (page - 1) * ITEMS_PER_PAGE,
    page * ITEMS_PER_PAGE
  );

  return (
    <div className="container py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Active Sessions</h1>
        <p className="text-muted-foreground">
          Manage your active sessions across devices
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Device Sessions</CardTitle>
              <CardDescription>
                {sessionList.length} active session(s)
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Refresh
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => logout()}
                disabled={isLoggingOut}
              >
                {isLoggingOut && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <LogOut className="mr-2 h-4 w-4" />
                Logout All
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : sessionList.length > 0 ? (
            <>
              <div className="space-y-4">
                {paginatedSessions.map((session) => {
                  const DeviceIcon = getDeviceIcon(session.userAgent);
                  return (
                    <div
                      key={session.id}
                      className="flex items-center justify-between rounded-lg border p-4"
                    >
                      <div className="flex items-center gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                          <DeviceIcon className="h-5 w-5 text-muted-foreground" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="text-sm font-medium">
                              {getDeviceName(session.userAgent)}
                            </p>
                            {session.isActive && (
                              <Badge variant="default" className="h-5 text-xs">
                                Active
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            IP: {session.ipAddress} &middot; Last active:{' '}
                            {session.lastActiveAt
                              ? format(new Date(session.lastActiveAt), 'MMM d, yyyy HH:mm')
                              : 'N/A'}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Created:{' '}
                            {format(new Date(session.createdAt), 'MMM d, yyyy HH:mm')}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">
                          {session.ipAddress}
                        </Badge>
                      </div>
                    </div>
                  );
                })}
              </div>

              {totalPages > 1 && (
                <div className="mt-4 flex items-center justify-between border-t pt-4">
                  <p className="text-sm text-muted-foreground">
                    Page {page} of {totalPages}
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
            </>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Shield className="mb-4 h-12 w-12 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No active sessions found</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
