'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuthStore } from '@/stores';
import { AuthCard, VerifyEmailForm } from '@minisource/auth-ui';

const verifySchema = z.object({
  code: z.string().length(6, 'Verification code must be 6 digits'),
});

type VerifyFormData = z.infer<typeof verifySchema>;

export default function VerifyEmailPage() {
  const { user } = useAuthStore();
  const [isSending, setIsSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [target, setTarget] = useState<'email' | 'phone'>('email');

  const form = useForm<VerifyFormData>({
    resolver: zodResolver(verifySchema),
  });

  const handleResend = async () => {
    setIsSending(true);
    try {
      const { authApi } = await import('@/api');
      await authApi.resendVerification({
        email: target === 'email' ? user?.email : undefined,
        phone: target === 'phone' ? user?.phone : undefined,
        type: target === 'email' ? 'email_verification' : 'phone_verification',
      });
      setSent(true);
    } catch {
      // error handled by interceptor
    }
    setIsSending(false);
  };

  const handleVerify = async (data: VerifyFormData) => {
    try {
      const { authApi } = await import('@/api');
      await authApi.verifyEmail({
        target: target === 'email' ? user?.email || '' : user?.phone || '',
        code: data.code,
        type: target === 'email' ? 'email_verification' : 'phone_verification',
      });
      alert('Verification successful!');
      window.location.reload();
    } catch {
      // error handled by interceptor
    }
  };

  return (
    <AuthCard
      title="Verify Your Contact"
      description="Verify your email address or phone number to activate your account"
    >
      <VerifyEmailForm
        target={target}
        onTargetChange={setTarget}
        targetValue={target === 'email' ? user?.email : user?.phone || undefined}
        isVerified={target === 'email' ? user?.emailVerified : user?.phoneVerified}
        hasPhone={!!user?.phone}
        code={{ value: undefined, onChange: (v) => form.register('code').onChange({ target: { value: v } } as React.ChangeEvent<HTMLInputElement>), error: form.formState.errors.code?.message }}
        codeSent={sent}
        onSendCode={handleResend}
        onVerify={form.handleSubmit(handleVerify)}
        isSending={isSending}
      />
    </AuthCard>
  );
}