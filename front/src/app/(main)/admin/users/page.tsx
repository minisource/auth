'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Badge,
  Button,
  Card,
  CardContent,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DataTable,
  Column,
  Pagination,
  SearchInput,
  FilterBar,
  ConfirmDialog,
  PageErrorState,
  PageHeader,
} from '@minisource/ui';
import { useAdminUsers, useDeleteUser, useToggleUserStatus, useUnlockUser } from '@/hooks';
import { CreateUserDialog } from '@/features/users';
import { isAppError, type AppError } from '@/shared/errors/app-error';
import { Lock, Unlock, Trash2, Edit, UserCircle } from 'lucide-react';
import { format } from 'date-fns';

const ITEMS_PER_PAGE = 10;

export default function AdminUsersPage() {
  const router = useRouter();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);

  const { data, isLoading, error, refetch } = useAdminUsers({
    page,
    pageSize: ITEMS_PER_PAGE,
    search: search || undefined,
  });

  // Extract user-friendly error message from AppError
  const errorMessage = error
    ? isAppError(error) ? (error as AppError).userMessage : (error as Error)?.message || 'Failed to load users'
    : null;

  const { mutate: deleteUser, isPending: isDeleting } = useDeleteUser();
  const { mutate: toggleStatus } = useToggleUserStatus();
  const { mutate: unlockUser } = useUnlockUser();

  const handleDelete = () => {
    if (!deleteTarget) return;
    deleteUser(deleteTarget.id, {
      onSuccess: () => setDeleteTarget(null),
    });
  };

  const totalPages = data?.meta?.totalPages ?? 1;

  const columns: Column<any>[] = [
    {
      key: 'user',
      header: 'User',
      render: (row) => (
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
            <UserCircle className="h-4 w-4 text-muted-foreground" />
          </div>
          <div>
            <p className="font-medium">{row.firstName || row.username || '—'}</p>
            <p className="text-xs text-muted-foreground">{row.email}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      align: 'center',
      render: (row) => (
        <Badge variant={row.isActive ? 'default' : 'secondary'}>
          {row.isActive ? 'Active' : 'Inactive'}
        </Badge>
      ),
    },
    {
      key: 'roles',
      header: 'Roles',
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.roles?.map((role: string) => (
            <Badge key={role} variant="outline" className="text-xs">
              {role}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      key: 'createdAt',
      header: 'Created',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-muted-foreground">
          {row.createdAt ? format(new Date(row.createdAt), 'MMM d, yyyy') : '—'}
        </span>
      ),
    },
  ];

  const renderRowActions = (row: any) => (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 12a.75.75 0 11-1.5 0 .75.75 0 011.5 0zM12.75 12a.75.75 0 11-1.5 0 .75.75 0 011.5 0zM18.75 12a.75.75 0 11-1.5 0 .75.75 0 011.5 0z" />
          </svg>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>Actions</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => router.push(`/admin/users/${row.id}`)}>
          <Edit className="me-2 h-4 w-4" /> View / Edit
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => toggleStatus(row.id)}>
          {row.isActive ? (
            <><Lock className="me-2 h-4 w-4" /> Deactivate</>
          ) : (
            <><Unlock className="me-2 h-4 w-4" /> Activate</>
          )}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => unlockUser(row.id)}>
          <Unlock className="me-2 h-4 w-4" /> Unlock
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="text-destructive"
          onClick={() => setDeleteTarget({ id: row.id, name: row.email })}
        >
          <Trash2 className="me-2 h-4 w-4" /> Delete
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );

  return (
    <div className="space-y-6">
      {/* Page-level error state when backend is unavailable and no data */}
      {error && !data ? (
        <PageErrorState
          variant="service-unavailable"
          title="Users Data Unavailable"
          description={errorMessage || 'Could not load user data from the Auth API.'}
          status={isAppError(error) ? (error as AppError).status : undefined}
          requestId={isAppError(error) ? (error as AppError).requestId : undefined}
          onRetry={() => refetch()}
        />
      ) : (
        <>
      <PageHeader
        title="Users"
        description="Manage user accounts and administrative access"
        actions={<CreateUserDialog onSuccess={() => refetch()} />}
      />

      <Card>
        <CardContent className="p-0">
          <FilterBar className="border-b px-4 py-3">
            <SearchInput
              value={search}
              onValueChange={(v) => { setSearch(v); setPage(1); }}
              placeholder="Search users..."
              className="w-full sm:w-80"
            />
          </FilterBar>

          <DataTable
            columns={columns}
            data={data?.data || []}
            getRowId={(row) => row.id}
            onRowClick={(row: any) => router.push(`/admin/users/${row.id}`)}
            renderRowActions={renderRowActions}
            isLoading={isLoading}
            error={errorMessage}
            emptyMessage="No users found"
            footer={
              <div className="px-4 py-3">
                <Pagination
                  page={page}
                  total={totalPages}
                  totalItems={data?.meta?.total}
                  pageSize={ITEMS_PER_PAGE}
                  onPageChange={setPage}
                />
              </div>
            }
          />
        </CardContent>
      </Card>

      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete User"
        description={`Are you sure you want to delete ${deleteTarget?.name}? This action cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={handleDelete}
        isConfirming={isDeleting}
        destructive
      />
        </>
      )}
    </div>
  );
}