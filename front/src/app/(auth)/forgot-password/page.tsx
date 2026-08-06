'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useForgotPassword, useResetPassword } from '@/hooks';
import { AuthCard, ForgotPasswordForm } from '@minisource/auth-ui';

const forgotSchema = z.object({
  email: z.string().email('Please enter a valid email').optional().or(z.literal('')),
  phone: z.string().min(10, 'Please enter a valid phone number').optional().or(z.literal('')),
});

const resetSchema = z.object({
  code: z.string().length(6, 'OTP must be 6 digits'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters'),
  confirmPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

type ForgotFormData = z.infer<typeof forgotSchema>;
type ResetFormData = z.infer<typeof resetSchema>;

export default function ForgotPasswordPage() {
  const [step, setStep] = useState<'email' | 'otp' | 'success'>('email');
  const [resetTarget, setResetTarget] = useState('');

  const { mutate: forgotPassword, isPending: isSending } = useForgotPassword();
  const { mutate: resetPassword, isPending: isResetting } = useResetPassword();

  const forgotForm = useForm<ForgotFormData>({
    resolver: zodResolver(forgotSchema),
  });

  const resetForm = useForm<ResetFormData>({
    resolver: zodResolver(resetSchema),
  });

  const onForgotSubmit = (data: ForgotFormData) => {
    const payload = data.email ? { email: data.email } : { phone: data.phone! };
    forgotPassword(payload, {
      onSuccess: () => {
        setResetTarget(data.email || data.phone || '');
        setStep('otp');
      },
    });
  };

  const onResetSubmit = (data: ResetFormData) => {
    resetPassword(
      { target: resetTarget, code: data.code, newPassword: data.newPassword },
      { onSuccess: () => setStep('success') }
    );
  };

  return (
    <AuthCard
      title={step === 'email' ? 'Forgot Password' : step === 'otp' ? 'Reset Password' : 'Password Reset'}
      description={
        step === 'email'
          ? 'Enter your email or phone to receive a reset code'
          : step === 'otp'
            ? `Enter the 6-digit code sent to ${resetTarget}`
            : undefined
      }
    >
      <ForgotPasswordForm
        step={step}
        email={{ value: undefined, onChange: (v) => forgotForm.register('email').onChange({ target: { value: v } } as React.ChangeEvent<HTMLInputElement>), error: forgotForm.formState.errors.email?.message }}
        phone={{ value: undefined, onChange: (v) => forgotForm.register('phone').onChange({ target: { value: v } } as React.ChangeEvent<HTMLInputElement>), error: forgotForm.formState.errors.phone?.message }}
        otpCode={{ value: undefined, onChange: (v) => resetForm.register('code').onChange({ target: { value: v } } as React.ChangeEvent<HTMLInputElement>), error: resetForm.formState.errors.code?.message }}
        newPassword={{ value: undefined, onChange: (v) => resetForm.register('newPassword').onChange({ target: { value: v } } as React.ChangeEvent<HTMLInputElement>), error: resetForm.formState.errors.newPassword?.message }}
        confirmPassword={{ value: undefined, onChange: (v) => resetForm.register('confirmPassword').onChange({ target: { value: v } } as React.ChangeEvent<HTMLInputElement>), error: resetForm.formState.errors.confirmPassword?.message }}
        resetTarget={resetTarget}
        onEmailSubmit={forgotForm.handleSubmit(onForgotSubmit)}
        onResetSubmit={resetForm.handleSubmit(onResetSubmit)}
        onBackToEmail={() => setStep('email')}
        onBackToLogin={() => {}}
        isSending={isSending}
        isResetting={isResetting}
      />
    </AuthCard>
  );
}