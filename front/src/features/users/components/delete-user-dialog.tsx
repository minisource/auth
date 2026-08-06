import * as React from 'react';
import { Trash2 } from 'lucide-react';
import { Button } from '@minisource/ui';
import { ConfirmActionDialog } from '@minisource/ui';
import { useDeleteUser } from '@/hooks';

interface DeleteUserDialogProps {
  userId: string;
  userDisplayName: string;
  onSuccess?: () => void;
}

export function DeleteUserDialog({
  userId,
  userDisplayName,
  onSuccess,
}: DeleteUserDialogProps) {
  const { mutateAsync: deleteUser, isPending: isDeleting } = useDeleteUser();

  const handleDelete = async () => {
    await deleteUser(userId);
    onSuccess?.();
  };

  return (
    <ConfirmActionDialog
      trigger={
        <Button variant="destructive" size="sm">
          <Trash2 className="mr-2 h-4 w-4" />
          Delete
        </Button>
      }
      title="Delete User"
      description={
        <span>
          Are you sure you want to delete <strong>{userDisplayName}</strong>? This action cannot be undone.
        </span>
      }
      confirmLabel="Delete"
      tone="destructive"
      pending={isDeleting}
      onConfirm={handleDelete}
    />
  );
}
