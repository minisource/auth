import * as React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
} from '@minisource/ui';
import { useCreateTenant } from '@/hooks';
import { Plus } from 'lucide-react';
import { TenantGuideModal } from './tenant-guide-modal';

const tenantSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  slug: z.string().min(2, 'Slug must be at least 2 characters'),
  displayName: z.string().optional(),
  description: z.string().optional(),
  domain: z.string().optional(),
  contactEmail: z.string().email().optional().or(z.literal('')),
});

type TenantFormData = z.infer<typeof tenantSchema>;

interface CreateTenantDialogProps {
  onSuccess?: () => void;
}

export function CreateTenantDialog({ onSuccess }: CreateTenantDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [createdTenant, setCreatedTenant] = React.useState<{ id: string; name: string; slug: string; domain?: string } | null>(null);
  const { mutate: createTenant, isPending: isCreating } = useCreateTenant();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TenantFormData>({
    resolver: zodResolver(tenantSchema),
  });

  const onSubmit = (formData: TenantFormData) => {
    createTenant(formData, {
      onSuccess: (data: any) => {
        setOpen(false);
        reset();
        onSuccess?.();
        if (data?.data?.id) {
          setCreatedTenant(data.data);
        }
      },
    });
  };

  return (
    <>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>
          <Button>
            <Plus className="mr-2 h-4 w-4" /> Create Tenant
          </Button>
        </DialogTrigger>
        <DialogContent className="sm:max-w-[550px]">
          <DialogHeader>
            <DialogTitle>Create New Tenant</DialogTitle>
            <DialogDescription>
              Add a new organization/tenant to the system.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="create-tenant-name">Name *</Label>
                <Input id="create-tenant-name" {...register('name')} placeholder="Acme Corp" />
                {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
              </div>
              <div className="space-y-2">
                <Label htmlFor="create-tenant-slug">Slug *</Label>
                <Input id="create-tenant-slug" {...register('slug')} placeholder="acme" />
                {errors.slug && <p className="text-xs text-destructive">{errors.slug.message}</p>}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="create-tenant-displayname">Display Name</Label>
                <Input id="create-tenant-displayname" {...register('displayName')} placeholder="Acme Corporation" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="create-tenant-domain">Custom Domain</Label>
                <Input id="create-tenant-domain" {...register('domain')} placeholder="acme.com" />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="create-tenant-email">Contact Email</Label>
              <Input id="create-tenant-email" type="email" {...register('contactEmail')} placeholder="admin@acme.com" />
              {errors.contactEmail && <p className="text-xs text-destructive">{errors.contactEmail.message}</p>}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isCreating}>
                {isCreating && <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />}
                Create Tenant
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Show Developer Guide Modal upon creation */}
      <TenantGuideModal
        tenant={createdTenant}
        open={!!createdTenant}
        onOpenChange={(o) => !o && setCreatedTenant(null)}
        isNew={true}
      />
    </>
  );
}
