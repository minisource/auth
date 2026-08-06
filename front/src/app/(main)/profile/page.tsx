'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Separator } from '@minisource/ui';
import { useCurrentUser, useUpdateProfile, useChangePassword } from '@/hooks';
import { useAuthStore } from '@/stores';
import {
  Loader2,
  Save,
  Lock,
  Mail,
  Phone,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import Link from 'next/link';

const profileSchema = z.object({
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
});

const passwordSchema = z
  .object({
    oldPassword: z.string().min(1, 'Current password is required'),
    newPassword: z.string().min(8, 'Password must be at least 8 characters'),
    confirmPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type ProfileFormData = z.infer<typeof profileSchema>;
type PasswordFormData = z.infer<typeof passwordSchema>;

export default function ProfilePage() {
  const { user } = useAuthStore();
  const { data: profile } = useCurrentUser();
  const { mutate: updateProfile, isPending: isUpdating } = useUpdateProfile();
  const { mutate: changePassword, isPending: isChangingPassword } = useChangePassword();

  const displayUser = profile || user;

  const profileForm = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    values: {
      firstName: displayUser?.firstName || '',
      lastName: displayUser?.lastName || '',
    },
  });

  const passwordForm = useForm<PasswordFormData>({
    resolver: zodResolver(passwordSchema),
  });

  const onProfileSubmit = (data: ProfileFormData) => {
    updateProfile(data);
  };

  const onPasswordSubmit = (data: PasswordFormData) => {
    changePassword({ oldPassword: data.oldPassword, newPassword: data.newPassword });
    passwordForm.reset();
  };

  if (!displayUser) {
    return (
      <div className="container flex items-center justify-center py-16">
        <p className="text-muted-foreground">Loading profile...</p>
      </div>
    );
  }

  return (
    <div className="container py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Profile Settings</h1>
        <p className="text-muted-foreground">
          Manage your account profile and security settings
        </p>
      </div>

      <div className="grid gap-8 lg:grid-cols-3">
        {/* Profile Info Sidebar */}
        <div className="space-y-6 lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle>Account Info</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <Mail className="h-4 w-4 text-muted-foreground" />
                <div className="flex-1">
                  <p className="text-sm font-medium">{displayUser.email}</p>
                  <div className="flex items-center gap-1">
                    {displayUser.emailVerified ? (
                      <>
                        <CheckCircle2 className="h-3 w-3 text-green-500" />
                        <span className="text-xs text-green-500">Verified</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="h-3 w-3 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground">Unverified</span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {displayUser.phone && (
                <div className="flex items-center gap-3">
                  <Phone className="h-4 w-4 text-muted-foreground" />
                  <div className="flex-1">
                    <p className="text-sm font-medium">{displayUser.phone}</p>
                    <div className="flex items-center gap-1">
                      {displayUser.phoneVerified ? (
                        <>
                          <CheckCircle2 className="h-3 w-3 text-green-500" />
                          <span className="text-xs text-green-500">Verified</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="h-3 w-3 text-muted-foreground" />
                          <span className="text-xs text-muted-foreground">Unverified</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              )}

              <Separator />

              <div>
                <p className="mb-2 text-sm text-muted-foreground">Roles</p>
                <div className="flex flex-wrap gap-2">
                  {displayUser.roles.map((role) => (
                    <Badge key={role} variant="secondary" className="capitalize">
                      {String(role).replace('_', ' ')}
                    </Badge>
                  ))}
                </div>
              </div>

              <div>
                <p className="mb-2 text-sm text-muted-foreground">Quick Links</p>
                <div className="space-y-2">
                  <Button variant="link" className="h-auto p-0 text-sm" asChild>
                    <Link href="/profile/sessions">View Active Sessions</Link>
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Profile Edit & Password Change */}
        <div className="space-y-6 lg:col-span-2">
          {/* Edit Profile */}
          <Card>
            <CardHeader>
              <CardTitle>Edit Profile</CardTitle>
              <CardDescription>Update your personal information</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={profileForm.handleSubmit(onProfileSubmit)} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="firstName">First Name</Label>
                    <Input
                      id="firstName"
                      {...profileForm.register('firstName')}
                      error={profileForm.formState.errors.firstName?.message}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="lastName">Last Name</Label>
                    <Input
                      id="lastName"
                      {...profileForm.register('lastName')}
                      error={profileForm.formState.errors.lastName?.message}
                    />
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

          {/* Change Password */}
          <Card>
            <CardHeader>
              <CardTitle>Change Password</CardTitle>
              <CardDescription>Update your account password</CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={passwordForm.handleSubmit(onPasswordSubmit)}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="oldPassword">Current Password</Label>
                  <Input
                    id="oldPassword"
                    type="password"
                    {...passwordForm.register('oldPassword')}
                    error={passwordForm.formState.errors.oldPassword?.message}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="newPassword">New Password</Label>
                  <Input
                    id="newPassword"
                    type="password"
                    placeholder="At least 8 characters"
                    {...passwordForm.register('newPassword')}
                    error={passwordForm.formState.errors.newPassword?.message}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm New Password</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    {...passwordForm.register('confirmPassword')}
                    error={passwordForm.formState.errors.confirmPassword?.message}
                  />
                </div>
                <Button type="submit" disabled={isChangingPassword}>
                  {isChangingPassword && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  <Lock className="mr-2 h-4 w-4" />
                  Update Password
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
