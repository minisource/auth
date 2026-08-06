'use client';

import { useEffect } from 'react';
import { Button } from '@minisource/ui';

interface GlobalErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function GlobalError({ error, reset }: GlobalErrorProps) {
  useEffect(() => {
    console.error('Global error:', error);
  }, [error]);

  return (
    <html lang="en">
      <body>
        <main className="flex min-h-screen flex-col items-center justify-center p-6">
          <div className="text-center">
            <h1 className="mb-2 text-4xl font-bold">Something went wrong!</h1>
            <p className="mb-2 text-muted-foreground">
              An unexpected error occurred. Please try again.
            </p>
            {error.digest && (
              <p className="mb-8 text-sm text-muted-foreground/75">
                Tracking ID: <code className="rounded bg-muted px-1.5 py-0.5 text-xs font-mono">{error.digest}</code>
              </p>
            )}
            {!error.digest && <div className="mb-8" />}
            <Button onClick={() => reset()}>Try Again</Button>
          </div>
        </main>
      </body>
    </html>
  );
}