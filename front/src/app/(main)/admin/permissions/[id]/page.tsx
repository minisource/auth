'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Separator } from '@minisource/ui';
import { adminApi } from '@/api';
import type { Permission } from '@/types/auth';
import {
  Loader2,
  ArrowLeft,
  Key,
  Calendar,
  FileText,
} from 'lucide-react';
import { format } from 'date-fns';

export default function AdminPermissionDetailPage({
  params: paramsPromise,
}: {
  params: Promise<{ id: string }>;
}) {
  const [params, setParams] = useState<{ id: string } | null>(null);
  const [permission, setPermission] = useState<Permission | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    paramsPromise.then(async (p) => {
      setParams(p);
      try {
        const data = await adminApi.getPermission(p.id);
        setPermission(data);
      } catch {
        // error handled
      }
      setIsLoading(false);
    });
  }, [paramsPromise]);

  if (!params || isLoading) {
    return (
      <div className="container flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!permission) {
    return (
      <div className="container py-8 text-center">
        <p className="text-muted-foreground">Permission not found</p>
        <Button variant="link" asChild>
          <Link href="/admin/permissions">Back to permissions</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="container py-8">
      <div className="mb-6">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/admin/permissions" className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Permissions
          </Link>
        </Button>
      </div>

      <div className="mx-auto max-w-2xl">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <Key className="h-6 w-6 text-primary" />
              </div>
              <div className="flex-1">
                <CardTitle className="text-2xl">{permission.name}</CardTitle>
                <CardDescription>Permission details</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex gap-4">
              <Badge variant="secondary" className="text-sm">
                Resource: {permission.resource}
              </Badge>
              <Badge variant="outline" className="text-sm">
                Action: {permission.action}
              </Badge>
            </div>

            <Separator />

            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <FileText className="mt-0.5 h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium">Description</p>
                  <p className="text-sm text-muted-foreground">
                    {permission.description || 'No description provided'}
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Calendar className="mt-0.5 h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium">Created</p>
                  <p className="text-sm text-muted-foreground">
                    {format(new Date(permission.createdAt), 'MMMM d, yyyy HH:mm')}
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Calendar className="mt-0.5 h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium">Last Updated</p>
                  <p className="text-sm text-muted-foreground">
                    {format(new Date(permission.updatedAt), 'MMMM d, yyyy HH:mm')}
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
