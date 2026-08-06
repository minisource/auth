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
  Switch,
} from '@minisource/ui';
import { useCreateUser } from '@/hooks';
import { Plus } from 'lucide-react';

const userSchema = z.object({
  email: z.string().email('Valid email is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  username: z.string().optional(),
  phone: z.string().optional(),
  isSuperAdmin: z.boolean().optional(),
});

type UserFormData = z.infer<typeof userSchema>;

interface CreateUserDialogProps {
  onSuccess?: () => void;
}

export function CreateUserDialog({ onSuccess }: CreateUserDialogProps) {
  const [open, setOpen] = React.useState(false);
  const { mutate: createUser, isPending: isCreating } = useCreateUser();

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors },
  } = useForm<UserFormData>({
    resolver: zodResolver(userSchema),
    defaultValues: {
      isSuperAdmin: false,
    },
  });

  const isSuperAdmin = watch('isSuperAdmin');

  const onSubmit = (formData: UserFormData) => {
    createUser(formData, {
      onSuccess: () => {
        setOpen(false);
        reset();
        onSuccess?.();
      },
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Add User
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[550px]">
        <DialogHeader>
          <DialogTitle>Create New User</DialogTitle>
          <DialogDescription>
            Add a new user account with full credentials and profile information.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="create-user-email">Email Address *</Label>
            <Input
              id="create-user-email"
              type="email"
              placeholder="user@example.com"
              {...register('email')}
            />
            {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
          </div>

          <div className="space-y-2">
            <Label htmlFor="create-user-password">Password *</Label>
            <Input
              id="create-user-password"
              type="password"
              placeholder="Min 8 characters"
              {...register('password')}
            />
            {errors.password && <p className="text-xs text-destructive">{errors.password.message}</p>}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="create-user-firstname">First Name</Label>
              <Input id="create-user-firstname" placeholder="John" {...register('firstName')} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-user-lastname">Last Name</Label>
              <Input id="create-user-lastname" placeholder="Doe" {...register('lastName')} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="create-user-username">Username</Label>
              <Input id="create-user-username" placeholder="johndoe" {...register('username')} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-user-phone">Phone Number</Label>
              <Input id="create-user-phone" placeholder="+989011793041" {...register('phone')} />
            </div>
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3 shadow-sm">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">Super Admin Privilege</Label>
              <p className="text-xs text-muted-foreground">Grant unrestricted system management access</p>
            </div>
            <Switch
              checked={isSuperAdmin}
              onCheckedChange={(checked) => setValue('isSuperAdmin', checked)}
            />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isCreating}>
              {isCreating && (
                <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              )}
              Create User
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
