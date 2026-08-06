'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, Input, Label, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Textarea } from '@minisource/ui';
import { useRoles, useCreateRole, useUpdateRole, useDeleteRole, usePermissions } from '@/hooks';
import { Shield, Plus, Loader2, Edit, Trash2, ChevronLeft, ChevronRight } from 'lucide-react';

const roleSchema = z.object({
  name: z.string().min(1, 'Role name is required'),
  description: z.string().optional(),
});

type RoleFormData = z.infer<typeof roleSchema>;

export default function AdminRolesPage() {
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const ITEMS_PER_PAGE = 10;

  const { data: roles, isLoading } = useRoles();

  const totalPages = Math.ceil((roles?.length || 0) / ITEMS_PER_PAGE);
  const paginatedRoles = roles?.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);
  const { data: permissions } = usePermissions();
  const { mutate: createRole, isPending: isCreating } = useCreateRole();
  const { mutate: updateRole, isPending: isUpdating } = useUpdateRole();
  const { mutate: deleteRole } = useDeleteRole();

  const createForm = useForm<RoleFormData>({
    resolver: zodResolver(roleSchema),
  });

  const editForm = useForm<RoleFormData>({
    resolver: zodResolver(roleSchema),
  });

  const editingRoleData = editingRole
    ? roles?.find((r) => r.id === editingRole)
    : null;

  const onCreateSubmit = (data: RoleFormData) => {
    createRole(data, {
      onSuccess: () => {
        setIsCreateOpen(false);
        createForm.reset();
      },
    });
  };

  const onEditSubmit = (data: RoleFormData) => {
    if (!editingRole) return;
    updateRole(
      { id: editingRole, data },
      {
        onSuccess: () => {
          setEditingRole(null);
          editForm.reset();
        },
      }
    );
  };

  const openEdit = (role: NonNullable<typeof roles>[0]) => {
    setEditingRole(role.id);
    editForm.setValue('name', role.name);
    editForm.setValue('description', role.description || '');
  };

  return (
    <div className="container py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Role Management</h1>
          <p className="text-muted-foreground">
            Create and manage access control roles
          </p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create Role
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Role</DialogTitle>
              <DialogDescription>
                Define a new role for access control
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={createForm.handleSubmit(onCreateSubmit)}>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="create-name">Role Name</Label>
                  <Input
                    id="create-name"
                    placeholder="e.g. editor, moderator"
                    {...createForm.register('name')}
                    error={createForm.formState.errors.name?.message}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="create-description">Description</Label>
                  <Textarea
                    id="create-description"
                    placeholder="Describe the role's purpose"
                    {...createForm.register('description')}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={isCreating}>
                  {isCreating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Create Role
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Roles List */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Roles</CardTitle>
            <CardDescription>{roles?.length || 0} roles defined</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Permissions</TableHead>
                  <TableHead>System</TableHead>
                  <TableHead className="w-[100px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-12 text-center">
                      <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : paginatedRoles && paginatedRoles.length > 0 ? (
                  paginatedRoles.map((role) => (
                    <TableRow key={role.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-muted-foreground" />
                          <span className="font-medium capitalize">
                            {role.name.replace('_', ' ')}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {role.description || '—'}
                      </TableCell>
                      <TableCell>
                        <div className="flex max-w-[200px] flex-wrap gap-1">
                          {role.permissions?.length > 0 ? (
                            role.permissions.slice(0, 3).map((perm) => (
                              <Badge key={perm.id} variant="outline" className="text-xs">
                                {perm.name}
                              </Badge>
                            ))
                          ) : (
                            <span className="text-xs text-muted-foreground">None</span>
                          )}
                          {role.permissions?.length > 3 && (
                            <Badge variant="secondary" className="text-xs">
                              +{role.permissions.length - 3}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={role.isSystem ? 'default' : 'secondary'} className="text-xs">
                          {role.isSystem ? 'System' : 'Custom'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {!role.isSystem && (
                            <>
                              <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => openEdit(role)}
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button variant="ghost" size="icon" className="text-destructive">
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>Delete Role</AlertDialogTitle>
                                    <AlertDialogDescription>
                                      Are you sure you want to delete the role &quot;{role.name}&quot;?
                                      This action cannot be undone.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                    <AlertDialogAction
                                      onClick={() => deleteRole(role.id)}
                                      className="bg-destructive text-destructive-foreground"
                                    >
                                      Delete
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))                  ) : (
                <TableRow>
                  <TableCell colSpan={5} className="py-12 text-center">
                    <Shield className="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No roles found</p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t px-6 py-4">
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
      </Card>

        {/* Permissions List */}
        <Card>
          <CardHeader>
            <CardTitle>Permissions</CardTitle>
            <CardDescription>{permissions?.length || 0} permissions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {permissions && permissions.length > 0 ? (
                permissions.map((perm) => (
                  <div
                    key={perm.id}
                    className="flex items-center justify-between rounded-lg border p-2 text-sm"
                  >
                    <div>
                      <p className="font-medium">{perm.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {perm.resource}:{perm.action}
                      </p>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {perm.resource}
                    </Badge>
                  </div>
                ))
              ) : (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  No permissions loaded
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Edit Role Dialog */}
      <Dialog open={!!editingRole} onOpenChange={(open) => !open && setEditingRole(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Role</DialogTitle>
            <DialogDescription>Update role details</DialogDescription>
          </DialogHeader>
          {editingRoleData && (
            <form onSubmit={editForm.handleSubmit(onEditSubmit)}>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="edit-name">Role Name</Label>
                  <Input
                    id="edit-name"
                    {...editForm.register('name')}
                    error={editForm.formState.errors.name?.message}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="edit-description">Description</Label>
                  <Textarea
                    id="edit-description"
                    {...editForm.register('description')}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={isUpdating}>
                  {isUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Update Role
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
