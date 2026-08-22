'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useLogin, useSendOTP, useVerifyOTP } from '@/hooks';
import { useAuthStore } from '@/stores';
import { config } from '@/config';
import { AuthCard, AuthFooter, LoginForm } from '@minisource/auth-ui';

const emailLoginSchema = z.object({
  email: z.string().email('Please enter a valid email'),
  password: z.string().min(1, 'Password is required'),
});

const otpSendSchema = z.object({
  phone: z.string().min(10, 'Please enter a valid phone number'),
});

const otpVerifySchema = z.object({
  code: z.string().length(6, 'OTP must be 6 digits'),
});

type EmailLoginFormData = z.infer<typeof emailLoginSchema>;
type OTPSendFormData = z.infer<typeof otpSendSchema>;
type OTPVerifyFormData = z.infer<typeof otpVerifySchema>;

export default function LoginPage() {
  const [otpSent, setOtpSent] = useState(false);
  const [otpTarget, setOtpTarget] = useState('');
  const [devInfo, setDevInfo] = useState<{ email: string; password: string } | undefined>(undefined);

  useEffect(() => {
    async function checkSeedStatus() {
      try {
        const { api } = await import('@/api');
        const res: any = await api.get('/auth/seed-status');
        if (res?.showNotice && res?.email && res?.defaultPassword) {
          setDevInfo({
            email: res.email,
            password: res.defaultPassword,
          });
        } else {
          setDevInfo(undefined);
        }
      } catch {
        setDevInfo(undefined);
      }
    }
    checkSeedStatus();
  }, []);

  const { rememberMe, setRememberMe } = useAuthStore();
  const router = useRouter();
  const { mutate: login, isPending: isLoggingIn } = useLogin();
  const { mutate: sendOTP, isPending: isSendingOTP } = useSendOTP();
  const { mutate: verifyOTP, isPending: isVerifyingOTP } = useVerifyOTP();

  const emailForm = useForm<EmailLoginFormData>({
    resolver: zodResolver(emailLoginSchema),
    defaultValues: { email: '', password: '' },
  });
  const otpSendForm = useForm<OTPSendFormData>({
    resolver: zodResolver(otpSendSchema),
    defaultValues: { phone: '' },
  });
  const otpVerifyForm = useForm<OTPVerifyFormData>({
    resolver: zodResolver(otpVerifySchema),
    defaultValues: { code: '' },
  });

  const onEmailLogin = (data: EmailLoginFormData) => {
    login({ ...data, rememberMe });
  };
  const onSendOTP = (data: OTPSendFormData) => {
    sendOTP(
      { phone: data.phone, type: 'login' },
      {
        onSuccess: () => {
          setOtpSent(true);
          setOtpTarget(data.phone);
        },
      }
    );
  };
  const onVerifyOTP = (data: OTPVerifyFormData) => {
    verifyOTP({ target: otpTarget, code: data.code, type: 'login', rememberMe });
  };

  return (
    <AuthCard
      title="Welcome back"
      description="Sign in to your Minisource account"
      footer={
        <AuthFooter text="Don&apos;t have an account?" linkText="Sign up" linkHref="/auth/register" />
      }
    >
      <LoginForm
        email={{
          value: emailForm.watch('email') || '',
          onChange: (v) =>
            emailForm.setValue('email', v, {
              shouldValidate: true,
              shouldDirty: true,
              shouldTouch: true,
            }),
          error: emailForm.formState.errors.email?.message,
        }}
        password={{
          value: emailForm.watch('password') || '',
          onChange: (v) =>
            emailForm.setValue('password', v, {
              shouldValidate: true,
              shouldDirty: true,
              shouldTouch: true,
            }),
          error: emailForm.formState.errors.password?.message,
        }}
        phone={{
          value: otpSendForm.watch('phone') || '',
          onChange: (v) =>
            otpSendForm.setValue('phone', v, {
              shouldValidate: true,
              shouldDirty: true,
              shouldTouch: true,
            }),
          error: otpSendForm.formState.errors.phone?.message,
        }}
        otpCode={{
          value: otpVerifyForm.watch('code') || '',
          onChange: (v) =>
            otpVerifyForm.setValue('code', v, {
              shouldValidate: true,
              shouldDirty: true,
              shouldTouch: true,
            }),
          error: otpVerifyForm.formState.errors.code?.message,
        }}
        otpSent={otpSent}
        otpTarget={otpTarget}
        isLoggingIn={isLoggingIn}
        isSendingOtp={isSendingOTP}
        isVerifyingOtp={isVerifyingOTP}
        onEmailSubmit={emailForm.handleSubmit(onEmailLogin)}
        onOtpSendSubmit={otpSendForm.handleSubmit(onSendOTP)}
        onOtpVerifySubmit={otpVerifyForm.handleSubmit(onVerifyOTP)}
        rememberMe={rememberMe}
        onRememberMeChange={setRememberMe}
        googleLoginUrl={`${config.api.baseUrl}/auth/google`}
        onForgotPassword={() => router.push('/auth/forgot-password')}
        forgotPasswordHref="/auth/forgot-password"
        onBackToOtpSend={() => setOtpSent(false)}
        devInfo={devInfo}
      />
    </AuthCard>
  );
}