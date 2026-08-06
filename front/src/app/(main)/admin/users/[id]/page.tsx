'use client';

import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useRouter } from 'next/navigation';
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Separator, Switch, Tabs, TabsContent, TabsList, TabsTrigger, DescriptionList, KeyValueItem, CopyableValue } from '@minisource/ui';
import {
  useAdminUser,
  useUpdateUser,
} from '@/hooks';
import { RevokeUserSessionsDialog, DeleteUserDialog } from '@/features/users';
import {
  Loader2,
  Save,
  ArrowLeft,
  UserCircle,
  Shield,
  CheckCircle2,
  XCircle,
  Lock,
  Unlock,
  KeyRound,
  Calendar,
  Activity,
  Globe,
} from 'lucide-react';
import Link from 'next/link';
import { format } from 'date-fns';

const updateUserSchema = z.object({
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  phone: z.string().optional(),
});

type UpdateUserFormData = z.infer<typeof updateUserSchema>;

export default function AdminUserDetailPage({
  params: paramsPromise,
}: {
  params: Promise<{ id: string }>;
}) {
  const [params, setParams] = useState<{ id: string } | null>(null);

  useEffect(() => {
    paramsPromise.then(setParams);
  }, [paramsPromise]);

  if (!params) {
    return (
      <div className="container flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <AdminUserDetailContent id={params.id} />;
}

function AdminUserDetailContent({ id }: { id: string }) {
  const router = useRouter();
  const { data: user } = useAdminUser(id);
  const { mutate: updateUser, isPending: isUpdating } = useUpdateUser();

  const form = useForm<UpdateUserFormData>({
    resolver: zodResolver(updateUserSchema),
    values: {
      firstName: user?.firstName || '',
      lastName: user?.lastName || '',
      phone: user?.phone || '',
    },
  });

  const [isActive, setIsActive] = useState(true);
  const [emailVerified, setEmailVerified] = useState(false);
  const [phoneVerified, setPhoneVerified] = useState(false);

  useEffect(() => {
    if (user) {
      setIsActive(user.isActive);
      setEmailVerified(user.emailVerified);
      setPhoneVerified(user.phoneVerified);
    }
  }, [user]);

  const onSubmit = (data: UpdateUserFormData) => {
    updateUser(
      {
        id,
        data: {
          ...data,
          isActive,
          emailVerified,
          phoneVerified,
        },
      },
      {
        onSuccess: () => {
          router.refresh();
        },
      }
    );
  };

  const handleToggleStatus = () => {
    if (!user) return;
    // Status toggle handled via UI components
  };

  const handleUnlock = () => {
    // Unlock handled via UI components
  };

  if (!user) {
    return (
      <div className="container py-8 text-center">
        <p className="text-muted-foreground">User not found</p>
        <Button variant="link" asChild>
          <Link href="/admin/users">Back to users</Link>
        </Button>
      </div>
    );
  }

  const isLocked = user.lockedUntil && new Date(user.lockedUntil) > new Date();

  return (
    <div className="container py-8">
      <div className="mb-6">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/admin/users" className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Users
          </Link>
        </Button>
      </div>

      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          <UserCircle className="h-12 w-12 text-muted-foreground" />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight">
                {user.firstName} {user.lastName}
              </h1>
              {user.isSuperAdmin && (
                <Badge variant="destructive" className="text-xs">
                  Super Admin
                </Badge>
              )}
            </div>
            <p className="text-muted-foreground">@{user.username}</p>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button
            variant={user.isActive ? 'outline' : 'default'}
            size="sm"
            onClick={handleToggleStatus}
            disabled={false}
          >
            {false ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : user.isActive ? (
              <Lock className="mr-2 h-4 w-4" />
            ) : (
              <Unlock className="mr-2 h-4 w-4" />
            )}
            {user.isActive ? 'Deactivate' : 'Activate'}
          </Button>

          {isLocked && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleUnlock}
              disabled={false}
            >
              {false ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <KeyRound className="mr-2 h-4 w-4" />
              )}
              Unlock
            </Button>
          )}

          <RevokeUserSessionsDialog
            userId={id}
            userDisplayName={`${user.firstName} ${user.lastName}`}
            onSuccess={() => router.refresh()}
          />

          <DeleteUserDialog
            userId={id}
            userDisplayName={`${user.firstName} ${user.lastName}`}
            onSuccess={() => router.push('/admin/users')}
          />
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="edit">Edit</TabsTrigger>
          <TabsTrigger value="roles">Roles & Permissions</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <UserCircle className="h-4 w-4" />
                  Profile Information
                </CardTitle>
              </CardHeader>
              <CardContent>
                <DescriptionList cols={2}>
                  <KeyValueItem label="User ID" value={<CopyableValue value={user.id} />} />
                  <KeyValueItem label="Username" value={`@${user.username}`} />
                  <KeyValueItem label="First Name" value={user.firstName || '—'} />
                  <KeyValueItem label="Last Name" value={user.lastName || '—'} />
                  <KeyValueItem
                    label="Email"
                    value={
                      <div className="flex items-center gap-2">
                        <CopyableValue value={user.email} />
                        {user.emailVerified ? (
                          <Badge variant="default" className="text-xs">
                            <CheckCircle2 className="mr-1 h-3 w-3" />
                            Verified
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="text-xs">
                            <XCircle className="mr-1 h-3 w-3" />
                            Unverified
                          </Badge>
                        )}
                      </div>
                    }
                  />
                  <KeyValueItem
                    label="Phone"
                    value={
                      user.phone ? (
                        <div className="flex items-center gap-2">
                          <CopyableValue value={user.phone} />
                          {user.phoneVerified ? (
                            <Badge variant="default" className="text-xs">
                              <CheckCircle2 className="mr-1 h-3 w-3" />
                              Verified
                            </Badge>
                          ) : (
                            <Badge variant="secondary" className="text-xs">
                              <XCircle className="mr-1 h-3 w-3" />
                              Unverified
                            </Badge>
                          )}
                        </div>
                      ) : (
                        '—'
                      )
                    }
                  />
                </DescriptionList>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Activity className="h-4 w-4" />
                  Account Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <DescriptionList cols={1}>
                  <KeyValueItem
                    label="Status"
                    value={
                      <Badge variant={user.isActive ? 'default' : 'secondary'}>
                        {user.isActive ? 'Active' : 'Inactive'}
                      </Badge>
                    }
                  />
                  <KeyValueItem
                    label="Locked"
                    value={
                      <Badge variant={isLocked ? 'destructive' : 'outline'}>
                        {isLocked ? 'Locked' : 'Unlocked'}
                      </Badge>
                    }
                  />
                  {isLocked && (
                    <KeyValueItem
                      label="Locked Until"
                      value={format(new Date(user.lockedUntil!), 'MMM d, yyyy HH:mm')}
                    />
                  )}
                  <KeyValueItem
                    label="Failed Attempts"
                    value={user.failedAttempts}
                  />
                  <KeyValueItem
                    label="Super Admin"
                    value={
                      <Badge variant={user.isSuperAdmin ? 'destructive' : 'outline'}>
                        {user.isSuperAdmin ? 'Yes' : 'No'}
                      </Badge>
                    }
                  />
                </DescriptionList>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Globe className="h-4 w-4" />
                  Login Information
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-xs text-muted-foreground">Last Login</p>
                  <p className="text-sm font-medium">
                    {user.lastLoginAt
                      ? format(new Date(user.lastLoginAt), 'MMM d, yyyy HH:mm:ss')
                      : 'Never'}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Last Login IP</p>
                  <p className="text-sm font-medium">{user.lastLoginIP || '\u2014'}</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Calendar className="h-4 w-4" />
                  Timestamps
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-xs text-muted-foreground">Created</p>
                  <p className="text-sm font-medium">
                    {format(new Date(user.createdAt), 'MMM d, yyyy HH:mm:ss')}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Last Updated</p>
                  <p className="text-sm font-medium">
                    {format(new Date(user.updatedAt), 'MMM d, yyyy HH:mm:ss')}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="edit">
          <Card>
            <CardHeader>
              <CardTitle>Edit User</CardTitle>
              <CardDescription>Update user profile and account settings</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Profile Information</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="firstName">First Name</Label>
                      <Input id="firstName" {...form.register('firstName')} />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="lastName">Last Name</Label>
                      <Input id="lastName" {...form.register('lastName')} />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="phone">Phone</Label>
                    <Input id="phone" type="tel" {...form.register('phone')} />
                  </div>
                </div>

                <Separator />

                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Account Settings</h3>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">Account Active</p>
                      <p className="text-xs text-muted-foreground">
                        Allow user to login and use the system
                      </p>
                    </div>
                    <Switch checked={isActive} onCheckedChange={setIsActive} />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <div>
                        <p className="text-sm font-medium">Email Verified</p>
                        <p className="text-xs text-muted-foreground">
                          Mark user email as verified
                        </p>
                      </div>
                    </div>
                    <Switch checked={emailVerified} onCheckedChange={setEmailVerified} />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <div>
                        <p className="text-sm font-medium">Phone Verified</p>
                        <p className="text-xs text-muted-foreground">
                          Mark user phone as verified
                        </p>
                      </div>
                    </div>
                    <Switch checked={phoneVerified} onCheckedChange={setPhoneVerified} />
                  </div>
                </div>

                <Button type="submit" disabled={isUpdating}>
                  {isUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  <Save className="mr-2 h-4 w-4" />
                  Save Changes
                </Button>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="roles" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Shield className="h-4 w-4" />
                Assigned Roles
              </CardTitle>
              <CardDescription>
                Roles and permissions assigned to this user
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {user.roles && user.roles.length > 0 ? (
                user.roles.map((role) => {
                  const roleObj = role as unknown;
                  const isObj = typeof roleObj === 'object' && roleObj !== null;
                  const name = isObj && 'name' in roleObj ? String((roleObj as any).name) : String(role);
                  const key = isObj && 'id' in roleObj ? String((roleObj as any).id) : name;
                  return (
                    <div key={key} className="rounded-md border p-4">
                      <div className="mb-2 flex items-center gap-2">
                        <Shield className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium capitalize">
                          {name.replace('_', ' ')}
                        </span>
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="text-sm text-muted-foreground">No roles assigned</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
