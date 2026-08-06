'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Input, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, CopyableValue, PageHeader } from '@minisource/ui';
import {
  Building2,
  Plus as _unusedPlus,
  Loader2,
  Edit,
  Trash2,
  Power,
  PowerOff,
  Users,
  UserPlus,
  Code,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import {
  useAdminTenants,
  useDeleteTenant,
  useToggleTenantStatus,
  useTenantMembers,
} from '@/hooks';
import {
  CreateTenantDialog,
  EditTenantDialog,
  RemoveTenantMemberDialog,
  TenantGuideModal,
} from '@/features/tenants';
import { format } from 'date-fns';

const tenantSchema = z.object({
  name: z.string().min(1, 'Tenant name is required'),
  slug: z.string().min(1, 'Slug is required').regex(/^[a-z0-9-]+$/, 'Slug must be lowercase alphanumeric with hyphens'),
  displayName: z.string().optional(),
  description: z.string().optional(),
  domain: z.string().optional(),
  contactEmail: z.string().email().optional().or(z.literal('')),
});

type TenantFormData = z.infer<typeof tenantSchema>;

export default function AdminTenantsPage() {
  const [page, setPage] = useState(1);
  const [, setIsCreateOpen] = useState(false);
  const [editingTenant, setEditingTenant] = useState<string | null>(null);
  const [membersTenantId, setMembersTenantId] = useState<string | null>(null);
  const [guideTenant, setGuideTenant] = useState<{ id: string; name: string; slug: string; domain?: string } | null>(null);

  const { data, isLoading, error, refetch } = useAdminTenants(page);
  const { mutate: deleteTenant } = useDeleteTenant();
  const { mutate: toggleStatus } = useToggleTenantStatus();
  const { data: members, refetch: refetchMembers } = useTenantMembers(membersTenantId || '');

  const editForm = useForm<TenantFormData>({ resolver: zodResolver(tenantSchema) });

  // createForm kept for future inline form usage
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _createForm = useForm<TenantFormData>({ resolver: zodResolver(tenantSchema) });

  const tenants = data?.data ?? [];
  const meta = data?.meta;
  const totalPages = meta?.totalPages ?? 1;

  const editingTenantData = editingTenant
    ? tenants.find((t) => t.id === editingTenant)
    : null;

  const selectedTenant = membersTenantId
    ? tenants.find((t) => t.id === membersTenantId)
    : null;

  const membersList = Array.isArray(members) ? members : [];

  const openEdit = (t: NonNullable<typeof tenants>[0]) => {
    setEditingTenant(t.id);
    editForm.setValue('name', t.name);
    editForm.setValue('slug', t.slug);
    editForm.setValue('displayName', t.displayName || '');
    editForm.setValue('description', t.description || '');
    editForm.setValue('domain', t.domain || '');
    editForm.setValue('contactEmail', t.contactEmail || '');
  };

  const getNextStatus = (currentStatus: string): 'active' | 'inactive' | 'suspended' => {
    switch (currentStatus) {
      case 'active': return 'inactive';
      case 'inactive': return 'active';
      case 'suspended': return 'active';
      default: return 'active';
    }
  };

  return (
    <div className="container py-8">
      <PageHeader
        title="Tenant Management"
        description="Manage tenants and organizations in the system"
        actions={<CreateTenantDialog onSuccess={() => refetch()} />}
      />

      {/* Tenants Table */}
      <Card>
        <CardHeader>
          <CardTitle>Tenants</CardTitle>
          <CardDescription>{meta?.total ?? 0} total tenants</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tenant ID</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Plan</TableHead>
                <TableHead>Domain</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[180px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-12 text-center">
                    <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : error ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-12 text-center text-destructive">
                    <p>Error loading tenants: {(error as any)?.message || 'Unknown error'}</p>
                  </TableCell>
                </TableRow>
              ) : tenants.length > 0 ? (
                tenants.map((tenant) => (
                  <TableRow key={tenant.id}>
                    <TableCell className="font-mono text-xs">
                      <CopyableValue value={tenant.id} />
                    </TableCell>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <Building2 className="h-4 w-4 text-muted-foreground" />
                        {tenant.name}
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="rounded bg-muted px-2 py-0.5 text-xs">{tenant.slug}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant={tenant.status === 'active' ? 'default' : tenant.status === 'trial' ? 'secondary' : 'destructive'}>
                        {tenant.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm capitalize">{tenant.plan}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{tenant.domain || '—'}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {format(new Date(tenant.createdAt), 'MMM d, yyyy')}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {/* Developer Guide */}
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setGuideTenant(tenant)}
                          title="Developer Integration Guide"
                        >
                          <Code className="h-4 w-4 text-primary" />
                        </Button>
                        {/* Status Toggle */}
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() =>
                            toggleStatus({
                              id: tenant.id,
                              status: getNextStatus(tenant.status),
                            })
                          }
                          title={tenant.status === 'active' ? 'Deactivate' : 'Activate'}
                        >
                          {tenant.status === 'active' ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
                        </Button>
                        {/* Members */}
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setMembersTenantId(tenant.id)}
                          title="Manage Members"
                        >
                          <Users className="h-4 w-4" />
                        </Button>
                        {/* Edit */}
                        <Button variant="ghost" size="icon" onClick={() => openEdit(tenant)}>
                          <Edit className="h-4 w-4" />
                        </Button>
                        {/* Delete */}
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="icon" className="text-destructive">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Delete Tenant</AlertDialogTitle>
                              <AlertDialogDescription>
                                Are you sure you want to delete &quot;{tenant.name}&quot;? This action cannot be undone.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteTenant(tenant.id)}
                                className="bg-destructive text-destructive-foreground"
                              >
                                Delete
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="py-12 text-center">
                    <Building2 className="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No tenants found</p>
                    <Button variant="link" onClick={() => setIsCreateOpen(true)}>
                      Create your first tenant
                    </Button>
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
            Page {meta.page} of {totalPages}
          </p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Edit Dialog */}
      <EditTenantDialog
        tenant={editingTenantData ? { id: editingTenantData.id, name: editingTenantData.name, slug: editingTenantData.slug } : null}
        onClose={() => setEditingTenant(null)}
        onSuccess={() => refetch()}
      />

      {/* Members Dialog */}
      <Dialog open={!!membersTenantId} onOpenChange={(o) => !o && setMembersTenantId(null)}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Tenant Members</DialogTitle>
            <DialogDescription>
              {selectedTenant ? (
                <>Manage members for <strong>{selectedTenant.name}</strong></>
              ) : (
                'Loading...'
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            {membersList.length > 0 ? (
              <div className="space-y-3">
                {membersList.map((member: any) => (
                  <div
                    key={member.userId}
                    className="flex items-center justify-between rounded-lg border p-3"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                        <Users className="h-4 w-4 text-primary" />
                      </div>
                      <div>
                        <p className="text-sm font-medium">
                          {member.user?.firstName} {member.user?.lastName}
                        </p>
                        <p className="text-xs text-muted-foreground">{member.user?.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {member.isOwner && (
                        <Badge variant="secondary" className="text-xs">Owner</Badge>
                      )}
                      {member.role && (
                        <Badge variant="outline" className="text-xs">{member.role.name}</Badge>
                      )}
                      {!member.isOwner && (
                        <RemoveTenantMemberDialog
                          tenantId={membersTenantId!}
                          userId={member.userId}
                          userDisplayName={`${member.user?.firstName} ${member.user?.lastName}`}
                          onSuccess={() => refetchMembers()}
                        />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center">
                <UserPlus className="mx-auto mb-2 h-8 w-8 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">No members found for this tenant</p>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" className="gap-2">
              <UserPlus className="h-4 w-4" />
              Invite Member
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Developer Integration Guide Modal */}
      <TenantGuideModal
        tenant={guideTenant}
        open={!!guideTenant}
        onOpenChange={(o) => !o && setGuideTenant(null)}
      />
    </div>
  );
}
