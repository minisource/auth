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
  Textarea,
} from '@minisource/ui';
import { useCreateServiceClient } from '@/hooks';
import { Plus } from 'lucide-react';

const clientSchema = z.object({
  name: z.string().min(1, 'Client name is required'),
  description: z.string().optional(),
  scopes: z.string().optional(),
});

type ClientFormData = z.infer<typeof clientSchema>;

interface CreateServiceClientDialogProps {
  onSuccess?: (res: { clientId: string; clientSecret: string; name: string }) => void;
}

export function CreateServiceClientDialog({ onSuccess }: CreateServiceClientDialogProps) {
  const [open, setOpen] = React.useState(false);
  const { mutate: createClient, isPending: isCreating } = useCreateServiceClient();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ClientFormData>({
    resolver: zodResolver(clientSchema),
  });

  const onSubmit = (formData: ClientFormData) => {
    const scopeArray = formData.scopes
      ? formData.scopes.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

    createClient(
      {
        name: formData.name,
        description: formData.description,
        scopes: scopeArray,
      },
      {
        onSuccess: (res: any) => {
          setOpen(false);
          reset();
          if (res?.clientSecret) {
            onSuccess?.({
              clientId: res.clientId || res.id,
              clientSecret: res.clientSecret,
              name: formData.name,
            });
          }
        },
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Create Client
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Service Client</DialogTitle>
          <DialogDescription>
            Register a new microservice for service-to-service auth
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="create-service-name">Service Name *</Label>
            <Input
              id="create-service-name"
              placeholder="e.g. analytics-service"
              {...register('name')}
            />
            {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="create-service-scopes">Scopes (comma separated)</Label>
            <Input
              id="create-service-scopes"
              placeholder="tokens:validate, logs:write"
              {...register('scopes')}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="create-service-desc">Description</Label>
            <Textarea
              id="create-service-desc"
              placeholder="Describe the service"
              {...register('description')}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isCreating}>
              {isCreating && <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />}
              Create Client
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
