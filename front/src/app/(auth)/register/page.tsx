'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button } from '@minisource/ui';
import { AuthCard, AuthFooter } from '@minisource/auth-ui';
import { Form, FormField, FormInput, FormMessage } from '@minisource/rhf';
import { useRegister } from '@/hooks';

const registerSchema = z
  .object({
    firstName: z.string().min(1, 'First name is required'),
    lastName: z.string().min(1, 'Last name is required'),
    email: z.string().email('Please enter a valid email'),
    phone: z.string().optional(),
    username: z.string().min(3, 'Username must be at least 3 characters').optional(),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type RegisterFormData = z.infer<typeof registerSchema>;

export default function RegisterPage() {
  const { mutate: registerUser, isPending } = useRegister();

  const form = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  });

  const onSubmit = (data: RegisterFormData) => {
    registerUser({
      email: data.email,
      password: data.password,
      username: data.username,
      firstName: data.firstName,
      lastName: data.lastName,
      phone: data.phone,
    });
  };

  return (
    <AuthCard
      title="Create an account"
      description="Enter your details to create a new account"
      footer={
        <AuthFooter
          text="Already have an account?"
          linkText="Sign in"
          linkHref="/auth/login"
        />
      }
    >
      <Form form={form} onSubmit={form.handleSubmit(onSubmit)}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <FormField name="firstName" label="First Name" required>
              <FormInput placeholder="John" autoComplete="given-name" />
              <FormMessage />
            </FormField>
            <FormField name="lastName" label="Last Name" required>
              <FormInput placeholder="Doe" autoComplete="family-name" />
              <FormMessage />
            </FormField>
          </div>

          <FormField name="username" label="Username">
            <FormInput placeholder="johndoe" autoComplete="username" />
            <FormMessage />
          </FormField>

          <FormField name="email" label="Email" required>
            <FormInput type="email" placeholder="name@example.com" autoComplete="email" />
            <FormMessage />
          </FormField>

          <FormField name="phone" label="Phone (optional)">
            <FormInput type="tel" placeholder="+1234567890" autoComplete="tel" />
            <FormMessage />
          </FormField>

          <FormField name="password" label="Password" required>
            <FormInput type="password" placeholder="At least 8 characters" autoComplete="new-password" />
            <FormMessage />
          </FormField>

          <FormField name="confirmPassword" label="Confirm Password" required>
            <FormInput type="password" placeholder="Confirm your password" autoComplete="new-password" />
            <FormMessage />
          </FormField>
        </div>

        <div className="pt-4">
          <Button type="submit" className="w-full" disabled={isPending}>
            {isPending && (
              <span className="me-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
            )}
            Create Account
          </Button>
        </div>
      </Form>
    </AuthCard>
  );
}