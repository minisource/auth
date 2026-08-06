import * as React from 'react';
import { LogOut } from 'lucide-react';
import { Button } from '@minisource/ui';
import { ConfirmActionDialog } from '@minisource/ui';
import { useAdminRevokeUserAllSessions } from '@/hooks';

interface RevokeUserSessionsDialogProps {
  userId: string;
  userDisplayName: string;
  onSuccess?: () => void;
}

export function RevokeUserSessionsDialog({
  userId,
  userDisplayName,
  onSuccess,
}: RevokeUserSessionsDialogProps) {
  const { mutateAsync: revokeSessions, isPending: isRevoking } =
    useAdminRevokeUserAllSessions();

  const handleRevoke = async () => {
    await revokeSessions(userId);
    onSuccess?.();
  };

  return (
    <ConfirmActionDialog
      trigger={
        <Button variant="outline" size="sm">
          <LogOut className="mr-2 h-4 w-4" />
          Revoke Sessions
        </Button>
      }
      title="Revoke All Sessions"
      description={`This will sign out ${userDisplayName} from all devices. They will need to log in again.`}
      confirmLabel="Revoke All"
      tone="destructive"
      pending={isRevoking}
      onConfirm={handleRevoke}
    />
  );
}
