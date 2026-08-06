'use client';

import { useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Textarea } from '@minisource/ui';
import { usePermissions, useCreatePermission, useUpdatePermission, useDeletePermission } from '@/hooks';
import {
  Key,
  Plus,
  Loader2,
  Edit,
  Trash2,
  Search,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { format } from 'date-fns';

const permissionSchema = z.object({
  name: z.string().min(1, 'Permission name is required'),
  description: z.string().optional(),
  resource: z.string().min(1, 'Resource is required'),
  action: z.string().min(1, 'Action is required'),
});

type PermissionFormData = z.infer<typeof permissionSchema>;

const ACTIONS = ['create', 'read', 'update', 'delete', 'manage', '*'];
const RESOURCES = [
  'users', 'roles', 'permissions', 'tokens',
  'notifications', 'logs', 'storage', 'comments',
  'feedback', 'tickets', 'payments', 'scheduler',
];

// Sentinel for the resource dropdown "show all" option (never a real resource)
const ALL_RESOURCES = '__all__';

export default function AdminPermissionsPage() {
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingPermission, setEditingPermission] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [page, setPage] = useState(1);

  const ITEMS_PER_PAGE = 10;

  const { data: permissions, isLoading } = usePermissions();

  // Union of known resources and resources actually present in the data
  const availableResources = useMemo(() => {
    const fromData = Array.from(
      new Set((permissions ?? []).map((p) => p.resource).filter(Boolean))
    );
    return Array.from(new Set([...RESOURCES, ...fromData])).sort();
  }, [permissions]);

  // Client-side filtering: resource dropdown (exact) + live search (substring)
  const filteredPermissions = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (permissions ?? []).filter((perm) => {
      const matchesResource = !resourceFilter || perm.resource === resourceFilter;
      const matchesSearch =
        !q ||
        perm.resource.toLowerCase().includes(q) ||
        perm.name.toLowerCase().includes(q) ||
        (perm.action || '').toLowerCase().includes(q);
      return matchesResource && matchesSearch;
    });
  }, [permissions, searchQuery, resourceFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredPermissions.length / ITEMS_PER_PAGE));
  // Clamp to a valid page so deletion/refetch can't leave the table out of range
  const currentPage = Math.min(page, totalPages);
  const paginatedPermissions = filteredPermissions.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );
  const { mutate: createPermission, isPending: isCreating } = useCreatePermission();
  const { mutate: updatePermission, isPending: isUpdating } = useUpdatePermission();
  const { mutate: deletePermission } = useDeletePermission();

  const createForm = useForm<PermissionFormData>({
    resolver: zodResolver(permissionSchema),
    defaultValues: { action: 'read' },
  });

  const editForm = useForm<PermissionFormData>({
    resolver: zodResolver(permissionSchema),
  });

  const editingPermissionData = editingPermission
    ? permissions?.find((p) => p.id === editingPermission)
    : null;

  const onCreateSubmit = (data: PermissionFormData) => {
    createPermission(data, {
      onSuccess: () => {
        setIsCreateOpen(false);
        createForm.reset();
      },
    });
  };

  const onEditSubmit = (data: PermissionFormData) => {
    if (!editingPermission) return;
    updatePermission(
      { id: editingPermission, data },
      {
        onSuccess: () => {
          setEditingPermission(null);
          editForm.reset();
        },
      }
    );
  };

  const openEdit = (perm: NonNullable<typeof permissions>[0]) => {
    setEditingPermission(perm.id);
    editForm.setValue('name', perm.name);
    editForm.setValue('description', perm.description || '');
    editForm.setValue('resource', perm.resource);
    editForm.setValue('action', perm.action);
  };

  return (
    <div className="container py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Permission Management</h1>
          <p className="text-muted-foreground">
            Define and manage system permissions
          </p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create Permission
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Permission</DialogTitle>
              <DialogDescription>Define a new permission rule</DialogDescription>
            </DialogHeader>
            <form onSubmit={createForm.handleSubmit(onCreateSubmit)}>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="create-name">Permission Name</Label>
                  <Input
                    id="create-name"
                    placeholder="e.g. users:create"
                    {...createForm.register('name')}
                    error={createForm.formState.errors.name?.message}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="create-resource">Resource</Label>
                    <Select
                      onValueChange={(v) => createForm.setValue('resource', v)}
                      defaultValue={createForm.watch('resource')}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select resource" />
                      </SelectTrigger>
                      <SelectContent>
                        {RESOURCES.map((r) => (
                          <SelectItem key={r} value={r}>
                            {r}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="create-action">Action</Label>
                    <Select
                      onValueChange={(v) => createForm.setValue('action', v)}
                      defaultValue={createForm.watch('action')}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select action" />
                      </SelectTrigger>
                      <SelectContent>
                        {ACTIONS.map((a) => (
                          <SelectItem key={a} value={a}>
                            {a}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="create-description">Description</Label>
                  <Textarea
                    id="create-description"
                    placeholder="Describe what this permission grants"
                    {...createForm.register('description')}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={isCreating}>
                  {isCreating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Create Permission
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Filter */}
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex flex-col gap-4 sm:flex-row">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by resource, name, or action..."
                className="pl-10"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <Select
              value={resourceFilter || ALL_RESOURCES}
              onValueChange={(v) => {
                setResourceFilter(v === ALL_RESOURCES ? '' : v);
                setPage(1);
              }}
            >
              <SelectTrigger
                className="w-full sm:w-[200px]"
                aria-label="Filter by resource"
              >
                <SelectValue placeholder="All resources" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL_RESOURCES}>All resources</SelectItem>
                {availableResources.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {(searchQuery || resourceFilter) && (
              <Button
                variant="ghost"
                onClick={() => {
                  setSearchQuery('');
                  setResourceFilter('');
                  setPage(1);
                }}
              >
                Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Permissions Table */}
      <Card>
        <CardHeader>
          <CardTitle>Permissions</CardTitle>
          <CardDescription>
            {filteredPermissions.length} of {permissions?.length || 0} permissions
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[70px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-12 text-center">
                    <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : paginatedPermissions && paginatedPermissions.length > 0 ? (
                paginatedPermissions.map((perm) => (
                  <TableRow key={perm.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Key className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium">{perm.name}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{perm.resource}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{perm.action}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {perm.description || '—'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {format(new Date(perm.createdAt), 'MMM d, yyyy')}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openEdit(perm)}
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
                              <AlertDialogTitle>Delete Permission</AlertDialogTitle>
                              <AlertDialogDescription>
                                Are you sure? This will remove the &quot;{perm.name}&quot; permission.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deletePermission(perm.id)}
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
                  <TableCell colSpan={6} className="py-12 text-center">
                    <Key className="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No permissions found</p>
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
              Page {currentPage} of {totalPages}
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

      {/* Edit Permission Dialog */}
      <Dialog
        open={!!editingPermission}
        onOpenChange={(open) => !open && setEditingPermission(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Permission</DialogTitle>
            <DialogDescription>Update permission details</DialogDescription>
          </DialogHeader>
          {editingPermissionData && (
            <form onSubmit={editForm.handleSubmit(onEditSubmit)}>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label>Permission Name</Label>
                  <Input {...editForm.register('name')} />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Resource</Label>
                    <Select
                      onValueChange={(v) => editForm.setValue('resource', v)}
                      defaultValue={editingPermissionData.resource}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RESOURCES.map((r) => (
                          <SelectItem key={r} value={r}>
                            {r}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Action</Label>
                    <Select
                      onValueChange={(v) => editForm.setValue('action', v)}
                      defaultValue={editingPermissionData.action}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ACTIONS.map((a) => (
                          <SelectItem key={a} value={a}>
                            {a}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Description</Label>
                  <Textarea {...editForm.register('description')} />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={isUpdating}>
                  {isUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Update Permission
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
