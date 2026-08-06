'use client';

import { Bell } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Button,
  cn,
} from '@minisource/ui';

interface Invitation {
  id: string;
  organization: {
    name: string;
  };
  role: string;
  expiresAt: string;
}

interface NotificationBellProps {
  /** List of pending invitations */
  invitations?: Invitation[];
  /** Accept invitation handler */
  onAccept?: (invitationId: string) => void;
  /** Whether the sidebar is collapsed */
  collapsed?: boolean;
  /** Custom class name */
  className?: string;
}

/**
 * Notification bell with invitation count badge.
 * Inspired by Dokploy's notification bell in sidebar header.
 */
export function NotificationBell({
  invitations = [],
  onAccept,
  collapsed,
  className,
}: NotificationBellProps) {
  const count = invitations.length;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn(
            'relative',
            collapsed ? 'h-8 w-8 p-1.5 mx-auto' : 'h-8 w-8',
            className,
          )}
        >
          <Bell className="size-4" />
          {count > 0 && (
            <span className="absolute -top-0.5 -right-0.5 flex size-4 items-center justify-center rounded-full bg-blue-500 text-[10px] font-medium text-white">
              {count > 9 ? '9+' : count}
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side={collapsed ? 'right' : 'bottom'} className="w-80">
        <DropdownMenuLabel>Pending Invitations</DropdownMenuLabel>
        <div className="flex flex-col gap-2">
          {count > 0 ? (
            invitations.map((invitation) => (
              <div key={invitation.id} className="flex flex-col gap-2">
                <DropdownMenuItem
                  className="flex flex-col items-start gap-1 p-3"
                  onSelect={(e) => e.preventDefault()}
                >
                  <div className="font-medium">
                    {invitation.organization.name}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Expires: {new Date(invitation.expiresAt).toLocaleString()}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Role: {invitation.role}
                  </div>
                </DropdownMenuItem>
                {onAccept && (
                  <div className="px-2 pb-2">
                    <Button
                      size="sm"
                      variant="secondary"
                      className="w-full"
                      onClick={() => onAccept(invitation.id)}
                    >
                      Accept Invitation
                    </Button>
                  </div>
                )}
                <DropdownMenuSeparator />
              </div>
            ))
          ) : (
            <DropdownMenuItem disabled>
              No pending invitations
            </DropdownMenuItem>
          )}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
