'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
  Badge,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  PageErrorState,
  PageHeader,
} from '@minisource/ui';
import {
  useAdminOAuthProviders,
  useCreateOAuthProvider,
  useUpdateOAuthProvider,
  useDeleteOAuthProvider,
  useToggleOAuthProvider,
} from '@/hooks';
import { useTenantStore } from '@/stores';
import { type AppError } from '@/shared/errors/app-error';
import { CredentialsGuide } from '@/features/oauth-providers/components/credentials-guide';
import {
  Loader2,
  Plus,
  Search,
  Key,
  Trash2,
  Edit,
  CheckCircle2,
  Activity,
  Globe,
  RefreshCw,
  Building2,
} from 'lucide-react';

const providerSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  type: z.string().min(1, 'Type is required'),
  tenantId: z.string().optional(),
  clientId: z.string().min(1, 'Client ID is required'),
  clientSecret: z.string().min(1, 'Client Secret is required'),
  redirectUrl: z.string().optional(),
  scopes: z.string().optional(),
  authUrl: z.string().optional(),
  tokenUrl: z.string().optional(),
  userInfoUrl: z.string().optional(),
});

type ProviderFormData = z.infer<typeof providerSchema>;

const PROVIDER_TYPES = [
  { value: 'google', label: 'Google' },
  { value: 'github', label: 'GitHub' },
  { value: 'facebook', label: 'Facebook' },
  { value: 'apple', label: 'Apple' },
  { value: 'custom', label: 'Custom' },
];

const DEFAULT_SCOPES: Record<string, string> = {
  google: 'openid email profile',
  github: 'read:user user:email',
  facebook: 'email public_profile',
  apple: 'name email',
};

export default function AdminOAuthProvidersPage() {
  const [page] = useState(1);
  const [search, setSearch] = useState('');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingProvider, setEditingProvider] = useState<any>(null);

  const { availableTenants } = useTenantStore();
  const { data, isLoading, error, refetch, isFetching } = useAdminOAuthProviders({ page, pageSize: 20 });
  const { mutate: createProvider, isPending: isCreating } = useCreateOAuthProvider();
  const { mutate: updateProvider, isPending: isUpdating } = useUpdateOAuthProvider();
  const { mutate: deleteProvider } = useDeleteOAuthProvider();
  const { mutate: toggleProvider } = useToggleOAuthProvider();

  const createForm = useForm<ProviderFormData>({
    resolver: zodResolver(providerSchema),
  });

  const editForm = useForm<ProviderFormData>({
    resolver: zodResolver(providerSchema),
  });

  const providers = data?.data ?? [];
  const meta = data?.meta;

  const filteredProviders = search
    ? providers.filter(
        (p: any) =>
          p.name.toLowerCase().includes(search.toLowerCase()) ||
          p.type.toLowerCase().includes(search.toLowerCase())
      )
    : providers;

  const onCreateSubmit = (formData: ProviderFormData) => {
    const payload = {
      ...formData,
      tenantId: formData.tenantId === 'global' || !formData.tenantId ? undefined : formData.tenantId,
    };
    createProvider(payload, {
      onSuccess: () => {
        setIsCreateOpen(false);
        createForm.reset();
      },
    });
  };

  const onEditSubmit = (formData: ProviderFormData) => {
    if (!editingProvider) return;
    const payload = {
      ...formData,
      tenantId: formData.tenantId === 'global' || !formData.tenantId ? undefined : formData.tenantId,
    };
    updateProvider(
      { id: editingProvider.id, data: payload },
      {
        onSuccess: () => {
          setEditingProvider(null);
          editForm.reset();
        },
      }
    );
  };

  const getTypeLabel = (type: string) => {
    return PROVIDER_TYPES.find((t) => t.value === type)?.label || type;
  };

  const appError = error ? (error as unknown as AppError) : null;

  return (
    <div className="container py-8 space-y-6">
      <PageHeader
        title="OAuth Providers"
        description="Manage OAuth provider configurations for social login and tenant SSO"
        actions={
          <>
            <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
              Refresh
            </Button>

            {/* Create Provider Dialog */}
            <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="mr-2 h-4 w-4" />
                  Add Provider
                </Button>
              </DialogTrigger>              <DialogContent className="sm:max-w-[600px]">
              <DialogHeader>
                <DialogTitle>Add OAuth Provider</DialogTitle>
                <DialogDescription>Configure a new OAuth provider for social login or specific tenant</DialogDescription>
              </DialogHeader>
              <div className="mb-1">
                <CredentialsGuide selectedType={createForm.watch('type')} />
              </div>
              <form onSubmit={createForm.handleSubmit(onCreateSubmit)}>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="create-name">Name *</Label>
                      <Input id="create-name" placeholder="My Google OAuth" {...createForm.register('name')} />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="create-type">Type *</Label>
                      <Select
                        onValueChange={(v) => {
                          createForm.setValue('type', v);
                          if (DEFAULT_SCOPES[v]) {
                            createForm.setValue('scopes', DEFAULT_SCOPES[v]);
                          }
                        }}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select type" />
                        </SelectTrigger>
                        <SelectContent>
                          {PROVIDER_TYPES.map((t) => (
                            <SelectItem key={t.value} value={t.value}>
                              {t.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  {/* Tenant Assignment Selection */}
                  <div className="space-y-2">
                    <Label htmlFor="create-tenant">Tenant Scope</Label>
                    <Select onValueChange={(v) => createForm.setValue('tenantId', v)}>
                      <SelectTrigger id="create-tenant">
                        <SelectValue placeholder="Global (Default for all tenants)" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="global">
                          <span className="flex items-center gap-2">
                            <Globe className="h-3.5 w-3.5" />
                            Global (Available to all tenants)
                          </span>
                        </SelectItem>
                        {availableTenants.map((tenant) => (
                          <SelectItem key={tenant.id} value={tenant.id}>
                            <span className="flex items-center gap-2">
                              <Building2 className="h-3.5 w-3.5" />
                              {tenant.name}
                            </span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="create-clientId">Client ID *</Label>
                    <Input id="create-clientId" {...createForm.register('clientId')} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="create-clientSecret">Client Secret *</Label>
                    <Input id="create-clientSecret" type="password" {...createForm.register('clientSecret')} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="create-redirectUrl">Redirect URL</Label>
                    <Input id="create-redirectUrl" placeholder="http://localhost:3003/auth/callback" {...createForm.register('redirectUrl')} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="create-scopes">Scopes</Label>
                    <Input id="create-scopes" placeholder="openid email profile" {...createForm.register('scopes')} />
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={isCreating}>
                    {isCreating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Create Provider
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* Edit Provider Dialog */}
          <Dialog open={!!editingProvider} onOpenChange={(o) => !o && setEditingProvider(null)}>
            <DialogContent className="sm:max-w-[550px]">
              <DialogHeader>
                <DialogTitle>Edit OAuth Provider</DialogTitle>
                <DialogDescription>Update OAuth provider credentials or tenant scope</DialogDescription>
              </DialogHeader>
              <form onSubmit={editForm.handleSubmit(onEditSubmit)}>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="edit-name">Name *</Label>
                      <Input id="edit-name" {...editForm.register('name')} />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-type">Type *</Label>
                      <Input id="edit-type" readOnly {...editForm.register('type')} className="bg-muted" />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="edit-tenant">Tenant Scope</Label>
                    <Select
                      defaultValue={editingProvider?.tenantId || 'global'}
                      onValueChange={(v) => editForm.setValue('tenantId', v)}
                    >
                      <SelectTrigger id="edit-tenant">
                        <SelectValue placeholder="Global (Default for all tenants)" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="global">
                          <span className="flex items-center gap-2">
                            <Globe className="h-3.5 w-3.5" />
                            Global (Available to all tenants)
                          </span>
                        </SelectItem>
                        {availableTenants.map((tenant) => (
                          <SelectItem key={tenant.id} value={tenant.id}>
                            <span className="flex items-center gap-2">
                              <Building2 className="h-3.5 w-3.5" />
                              {tenant.name}
                            </span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="edit-clientId">Client ID *</Label>
                    <Input id="edit-clientId" {...editForm.register('clientId')} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="edit-clientSecret">Client Secret *</Label>
                    <Input id="edit-clientSecret" type="password" {...editForm.register('clientSecret')} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="edit-redirectUrl">Redirect URL</Label>
                    <Input id="edit-redirectUrl" {...editForm.register('redirectUrl')} />
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={isUpdating}>
                    {isUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Update Provider
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </>
      }
    />

      {/* Primary Overview Cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Providers</p>
                <p className="text-2xl font-bold">{meta?.total ?? 0}</p>
              </div>
              <Key className="h-8 w-8 text-muted-foreground/40" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active</p>
                <p className="text-2xl font-bold text-green-600">
                  {providers.filter((p: any) => p.isEnabled).length}
                </p>
              </div>
              <CheckCircle2 className="h-8 w-8 text-green-600/40" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Logins</p>
                <p className="text-2xl font-bold">
                  {providers.reduce((sum: number, p: any) => sum + (p.totalLogins || 0), 0)}
                </p>
              </div>
              <Activity className="h-8 w-8 text-muted-foreground/40" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search Bar */}
      <Card>
        <CardContent className="pt-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search providers..."
              className="pl-10"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Providers Table OR Explicit Error View */}
      <Card>
        <CardContent className="p-0">
          {appError ? (
            <div className="p-6">
              <PageErrorState
                variant="service-unavailable"
                title="Failed to Load OAuth Providers"
                description={appError.userMessage || 'An HTTP 500 error occurred while fetching provider configurations.'}
                requestId={appError.requestId}
                status={appError.status}
                onRetry={refetch}
                technicalDetails={appError.message}
              />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Logins</TableHead>
                  <TableHead className="w-[150px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-12 text-center">
                      <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : filteredProviders.length > 0 ? (
                  filteredProviders.map((provider: any) => (
                    <TableRow key={provider.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Globe className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <p className="text-sm font-medium">{provider.name}</p>
                            <p className="text-xs text-muted-foreground">
                              {provider.clientId?.substring(0, 20)}...
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{getTypeLabel(provider.type)}</Badge>
                      </TableCell>
                      <TableCell>
                        {provider.tenant ? (
                          <Badge variant="secondary" className="gap-1 text-[11px]">
                            <Building2 className="h-3 w-3" />
                            {provider.tenant.name}
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="gap-1 text-[11px] text-muted-foreground">
                            <Globe className="h-3 w-3" />
                            Global
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={provider.isEnabled}
                          onCheckedChange={() => toggleProvider(provider.id)}
                        />
                      </TableCell>
                      <TableCell className="text-sm">{provider.totalLogins || 0}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => {
                              setEditingProvider(provider);
                              editForm.reset({
                                name: provider.name,
                                type: provider.type,
                                tenantId: provider.tenantId || 'global',
                                clientId: provider.clientId,
                                clientSecret: provider.clientSecret,
                                redirectUrl: provider.redirectUrl,
                                scopes: provider.scopes,
                                authUrl: provider.authUrl,
                                tokenUrl: provider.tokenUrl,
                                userInfoUrl: provider.userInfoUrl,
                              });
                            }}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive">
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Delete OAuth Provider</AlertDialogTitle>
                                <AlertDialogDescription>
                                  Are you sure you want to delete &quot;{provider.name}&quot;? Users will no longer be able to log in with this provider.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => deleteProvider(provider.id)}
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
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
                    <TableCell colSpan={6} className="py-12 text-center text-muted-foreground">
                      No OAuth Providers configured yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
