'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input } from '@minisource/ui';
import { useRole, usePermissions } from '@/hooks';
import { adminApi } from '@/api';
import {
  Loader2,
  ArrowLeft,
  Shield,
  Plus,
  X,
  Search,
} from 'lucide-react';
import { toast } from 'sonner';

export default function AdminRoleDetailPage({
  params: paramsPromise,
}: {
  params: Promise<{ id: string }>;
}) {
  const [params, setParams] = useState<{ id: string } | null>(null);

  useEffect(() => {
    paramsPromise.then(setParams);
  }, [paramsPromise]);

  if (!params) {
    return (
      <div className="container flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <AdminRoleDetailContent id={params.id} />;
}

function AdminRoleDetailContent({ id }: { id: string }) {
  const { data: role, isLoading } = useRole(id);
  const { data: allPermissions } = usePermissions();
  const [searchTerm, setSearchTerm] = useState('');
  const [isAssigning, setIsAssigning] = useState<string | null>(null);
  const [isRemoving, setIsRemoving] = useState<string | null>(null);

  const assignedPermissionIds = new Set(role?.permissions?.map((p) => p.id) || []);
  const availablePermissions = (allPermissions || []).filter(
    (p) => !assignedPermissionIds.has(p.id)
  );

  const filteredAvailable = availablePermissions.filter(
    (p) =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.resource.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleAssign = async (permissionId: string) => {
    setIsAssigning(permissionId);
    try {
      await adminApi.assignPermissionToRole(id, permissionId);
      toast.success('Permission assigned to role');
      window.location.reload();
    } catch {
      toast.error('Failed to assign permission');
    }
    setIsAssigning(null);
  };

  const handleRemove = async (permissionId: string) => {
    setIsRemoving(permissionId);
    try {
      await adminApi.removePermissionFromRole(id, permissionId);
      toast.success('Permission removed from role');
      window.location.reload();
    } catch {
      toast.error('Failed to remove permission');
    }
    setIsRemoving(null);
  };

  if (isLoading) {
    return (
      <div className="container flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!role) {
    return (
      <div className="container py-8 text-center">
        <p className="text-muted-foreground">Role not found</p>
        <Button variant="link" asChild>
          <Link href="/admin/roles">Back to roles</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="container py-8">
      <div className="mb-6">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/admin/roles" className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Roles
          </Link>
        </Button>
      </div>

      <div className="mb-8">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold capitalize">
              {role.name.replace(/_/g, ' ')}
            </h1>
            <p className="text-muted-foreground">{role.description || 'No description'}</p>
          </div>
          <Badge variant={role.isSystem ? 'default' : 'secondary'} className="ml-auto">
            {role.isSystem ? 'System Role' : 'Custom Role'}
          </Badge>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Assigned Permissions */}
        <Card>
          <CardHeader>
            <CardTitle>Assigned Permissions</CardTitle>
            <CardDescription>
              {role.permissions?.length || 0} permissions assigned
            </CardDescription>
          </CardHeader>
          <CardContent>
            {role.permissions && role.permissions.length > 0 ? (
              <div className="space-y-2">
                {role.permissions.map((perm) => (
                  <div
                    key={perm.id}
                    className="flex items-center justify-between rounded-lg border p-3"
                  >
                    <div className="flex-1">
                      <p className="text-sm font-medium">{perm.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {perm.resource}:{perm.action}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">
                        {perm.resource}
                      </Badge>
                      {!role.isSystem && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive"
                          onClick={() => handleRemove(perm.id)}
                          disabled={isRemoving === perm.id}
                        >
                          {isRemoving === perm.id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <X className="h-3 w-3" />
                          )}
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No permissions assigned to this role
              </p>
            )}
          </CardContent>
        </Card>

        {/* Available Permissions */}
        {!role.isSystem && (
          <Card>
            <CardHeader>
              <CardTitle>Available Permissions</CardTitle>
              <CardDescription>Assign permissions to this role</CardDescription>
              <div className="relative mt-2">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search permissions..."
                  className="pl-10"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </CardHeader>
            <CardContent>
              {filteredAvailable.length > 0 ? (
                <div className="max-h-[500px] space-y-2 overflow-y-auto">
                  {filteredAvailable.map((perm) => (
                    <div
                      key={perm.id}
                      className="flex items-center justify-between rounded-lg border p-3"
                    >
                      <div className="flex-1">
                        <p className="text-sm font-medium">{perm.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {perm.resource}:{perm.action}
                          {perm.description ? ` — ${perm.description}` : ''}
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-green-600"
                        onClick={() => handleAssign(perm.id)}
                        disabled={isAssigning === perm.id}
                      >
                        {isAssigning === perm.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Plus className="h-3 w-3" />
                        )}
                      </Button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  {searchTerm
                    ? 'No permissions match your search'
                    : 'All permissions are already assigned'}
                </p>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
