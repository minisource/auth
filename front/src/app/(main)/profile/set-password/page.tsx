'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } from '@minisource/ui';
import { useSetPassword } from '@/hooks';
import { Loader2, Lock, KeyRound } from 'lucide-react';

const setPasswordSchema = z
  .object({
    password: z.string().min(8, 'Password must be at least 8 characters'),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type SetPasswordFormData = z.infer<typeof setPasswordSchema>;

export default function SetPasswordPage() {
  const { mutate: setPassword, isPending } = useSetPassword();

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<SetPasswordFormData>({
    resolver: zodResolver(setPasswordSchema),
  });

  const onSubmit = (data: SetPasswordFormData) => {
    setPassword({ password: data.password }, { onSuccess: () => reset() });
  };

  return (
    <div className="container py-8">
      <div className="mx-auto max-w-lg">
        <Card>
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <KeyRound className="h-6 w-6 text-primary" />
            </div>
            <CardTitle className="text-2xl font-bold">Set Your Password</CardTitle>
            <CardDescription>
              You logged in via OTP. Set a password so you can also login with email and password.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="password">New Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="At least 8 characters"
                  {...register('password')}
                  error={errors.password?.message}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="Confirm your password"
                  {...register('confirmPassword')}
                  error={errors.confirmPassword?.message}
                />
              </div>
              <Button type="submit" className="w-full gap-2" disabled={isPending}>
                {isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                <Lock className="h-4 w-4" />
                Set Password
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
