import * as React from 'react';
import { UserMinus } from 'lucide-react';
import { Button } from '@minisource/ui';
import { ConfirmActionDialog } from '@minisource/ui';
import { useRemoveTenantMember } from '@/hooks';

interface RemoveTenantMemberDialogProps {
  tenantId: string;
  userId: string;
  userDisplayName: string;
  onSuccess?: () => void;
}

export function RemoveTenantMemberDialog({
  tenantId,
  userId,
  userDisplayName,
  onSuccess,
}: RemoveTenantMemberDialogProps) {
  const { mutateAsync: removeMember, isPending: isRemoving } =
    useRemoveTenantMember();

  const handleRemove = async () => {
    await removeMember({ tenantId, userId });
    onSuccess?.();
  };

  return (
    <ConfirmActionDialog
      trigger={
        <Button variant="ghost" size="icon" className="text-destructive h-8 w-8">
          <UserMinus className="h-3.5 w-3.5" />
        </Button>
      }
      title="Remove Member"
      description={`Remove ${userDisplayName} from this tenant?`}
      confirmLabel="Remove"
      tone="destructive"
      pending={isRemoving}
      onConfirm={handleRemove}
    />
  );
}
