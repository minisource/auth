'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Input, Label, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Textarea, PageHeader } from '@minisource/ui';
import { CreateServiceClientDialog } from '@/features/service-clients';
import {
  useServiceClients,
  useUpdateServiceClient,
  useDeleteServiceClient,
  useToggleServiceClientStatus,
  useRotateServiceClientSecret,
} from '@/hooks';
import {
  Server,
  Loader2,
  Copy,
  CheckCircle2,
  Edit,
  Trash2,
  RotateCcw,
  Power,
  PowerOff,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { toast } from 'sonner';

const clientSchema = z.object({
  name: z.string().min(1, 'Client name is required'),
  description: z.string().optional(),
  scopes: z.string().optional(),
});

type ClientFormData = z.infer<typeof clientSchema>;

export default function AdminServiceClientsPage() {
  const [editingClient, setEditingClient] = useState<string | null>(null);
  const [createdSecret, setCreatedSecret] = useState<{
    clientId: string;
    clientSecret: string;
    name: string;
  } | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const ITEMS_PER_PAGE = 10;

  const { data: clients, isLoading, error } = useServiceClients();


  const { mutate: updateClient, isPending: isUpdating } = useUpdateServiceClient();
  const { mutate: deleteClient } = useDeleteServiceClient();
  const { mutate: toggleStatus } = useToggleServiceClientStatus();
  const { mutate: rotateSecret, isPending: isRotating } = useRotateServiceClientSecret();

  const editForm = useForm<ClientFormData>({ resolver: zodResolver(clientSchema) });

  const editingClientData = editingClient
    ? Array.isArray(clients) ? clients.find((c) => c.id === editingClient || c.clientId === editingClient) : null
    : null;

  const onEditSubmit = (data: ClientFormData) => {
    if (!editingClient) return;
    const scopes = data.scopes
      ? data.scopes.split(',').map((s) => s.trim()).filter(Boolean)
      : undefined;
    updateClient(
      { id: editingClient, data: { name: data.name, description: data.description, scopes } },
      {
        onSuccess: () => {
          setEditingClient(null);
          editForm.reset();
        },
      }
    );
  };

  const openEdit = (client: any) => {
    setEditingClient(client.id || client.clientId);
    editForm.setValue('name', client.name);
    editForm.setValue('description', client.description || '');
    editForm.setValue('scopes', Array.isArray(client.scopes) ? client.scopes.join(', ') : client.scopes || '');
  };

  const handleRotateSecret = (id: string) => {
    rotateSecret(id, {
      onSuccess: (result: any) => {
        setRotatedSecret(result.clientSecret || '');
      },
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const clientList = Array.isArray(clients) ? clients : [];
  const paginatedClients = clientList.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);
  const totalPages = Math.ceil(clientList.length / ITEMS_PER_PAGE);

  return (
    <div className="container py-8">
      <PageHeader
        title="Service Clients"
        description="Manage service-to-service authentication clients"
        actions={
          <CreateServiceClientDialog
            onSuccess={(secretData) => setCreatedSecret(secretData)}
          />
        }
      />

      {/* Created / Rotated Secret Dialogs */}
      <Dialog open={!!createdSecret} onOpenChange={(o) => !o && setCreatedSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
              <CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <DialogTitle className="text-center">Client Created</DialogTitle>
            <DialogDescription className="text-center">
              Save these credentials — the secret will not be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Client ID</Label>
              <div className="flex gap-2">
                <Input readOnly value={createdSecret?.clientId || ''} />
                <Button variant="outline" size="icon" onClick={() => copyToClipboard(createdSecret?.clientId || '')}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <div>
              <Label>Client Secret</Label>
              <div className="flex gap-2">
                <Input readOnly value={createdSecret?.clientSecret || ''} className="font-mono" />
                <Button variant="outline" size="icon" onClick={() => copyToClipboard(createdSecret?.clientSecret || '')}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setCreatedSecret(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!rotatedSecret} onOpenChange={(o) => !o && setRotatedSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900">
              <AlertTriangle className="h-6 w-6 text-amber-600 dark:text-amber-400" />
            </div>
            <DialogTitle className="text-center">Secret Rotated</DialogTitle>
            <DialogDescription className="text-center">
              The new secret is shown once. Save it now.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>New Client Secret</Label>
              <div className="flex gap-2">
                <Input readOnly value={rotatedSecret || ''} className="font-mono" />
                <Button variant="outline" size="icon" onClick={() => copyToClipboard(rotatedSecret || '')}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setRotatedSecret(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Clients List */}
      <Card>
        <CardHeader>
          <CardTitle>All Clients</CardTitle>
          <CardDescription>{clientList.length} service client{clientList.length !== 1 ? 's' : ''} registered</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Client ID</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-[180px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-12 text-center">
                    <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : error ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-12 text-center text-destructive">
                    <p>Error loading service clients: {(error as any)?.message || 'Unknown error'}</p>
                  </TableCell>
                </TableRow>
              ) : paginatedClients.length > 0 ? (
                paginatedClients.map((client: any) => (
                  <TableRow key={client.id || client.clientId}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        {client.name}
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="rounded bg-muted px-2 py-0.5 text-xs">{client.clientId}</code>
                    </TableCell>
                    <TableCell>
                      <div className="flex max-w-[200px] flex-wrap gap-1">
                        {(Array.isArray(client.scopes) ? client.scopes : client.scopes?.split(',') || []).map((scope: string) => (
                          <Badge key={scope.trim()} variant="outline" className="text-xs">
                            {scope.trim()}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                      {client.description || '—'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={client.isActive !== false ? 'default' : 'secondary'}>
                        {client.isActive !== false ? 'Active' : 'Inactive'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="icon" onClick={() => openEdit(client)} title="Edit">
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() =>
                            toggleStatus({
                              id: client.id || client.clientId,
                              status: client.isActive !== false ? 'inactive' : 'active',
                            })
                          }
                          title={client.isActive !== false ? 'Deactivate' : 'Activate'}
                        >
                          {client.isActive !== false ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleRotateSecret(client.id || client.clientId)}
                          disabled={isRotating}
                          title="Rotate Secret"
                        >
                          <RotateCcw className="h-4 w-4" />
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="icon" className="text-destructive" title="Delete">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Delete Service Client</AlertDialogTitle>
                              <AlertDialogDescription>
                                Are you sure you want to delete &quot;{client.name}&quot;? This action cannot be undone.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteClient(client.id || client.clientId)}
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
                    <Server className="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No service clients found</p>
                    <Button variant="link" onClick={() => setIsCreateOpen(true)}>
                      Create your first client
                    </Button>
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

      {/* Edit Dialog */}
      <Dialog open={!!editingClient} onOpenChange={(o) => !o && setEditingClient(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Service Client</DialogTitle>
            <DialogDescription>Update client details and scopes</DialogDescription>
          </DialogHeader>
          {editingClientData && (
            <form onSubmit={editForm.handleSubmit(onEditSubmit)}>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label>Service Name</Label>
                  <Input {...editForm.register('name')} />
                </div>
                <div className="space-y-2">
                  <Label>Scopes</Label>
                  <Input {...editForm.register('scopes')} />
                </div>
                <div className="space-y-2">
                  <Label>Description</Label>
                  <Textarea {...editForm.register('description')} />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={isUpdating}>
                  {isUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Update Client
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
