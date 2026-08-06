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
  Input,
  Label,
} from '@minisource/ui';
import { useUpdateTenant } from '@/hooks';

const tenantSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  slug: z.string().min(2, 'Slug must be at least 2 characters'),
});

type TenantFormData = z.infer<typeof tenantSchema>;

interface EditTenantDialogProps {
  tenant: { id: string; name: string; slug: string } | null;
  onClose: () => void;
  onSuccess?: () => void;
}

export function EditTenantDialog({ tenant, onClose, onSuccess }: EditTenantDialogProps) {
  const { mutate: updateTenant, isPending: isUpdating } = useUpdateTenant();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TenantFormData>({
    resolver: zodResolver(tenantSchema),
    values: tenant ? { name: tenant.name, slug: tenant.slug } : undefined,
  });

  const onSubmit = (formData: TenantFormData) => {
    if (!tenant) return;
    updateTenant(
      { id: tenant.id, data: formData },
      {
        onSuccess: () => {
          onClose();
          reset();
          onSuccess?.();
        },
      }
    );
  };

  return (
    <Dialog open={!!tenant} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Edit Tenant</DialogTitle>
          <DialogDescription>Update tenant details.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="edit-tenant-name">Name *</Label>
            <Input id="edit-tenant-name" {...register('name')} />
            {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-tenant-slug">Slug *</Label>
            <Input id="edit-tenant-slug" {...register('slug')} />
            {errors.slug && <p className="text-xs text-destructive">{errors.slug.message}</p>}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isUpdating}>
              {isUpdating && <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />}
              Save Changes
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
