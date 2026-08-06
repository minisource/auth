'use client';

import { HeaderControls } from '@/components/layout/header-controls';

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen items-center justify-center bg-muted/50 p-4">
      <div className="absolute end-4 top-4 flex items-center gap-2">
        <HeaderControls />
      </div>
      <div className="w-full max-w-md">{children}</div>
    </div>
  );
}
