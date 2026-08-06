'use client';

import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from '@minisource/ui';
import { useLinkedAccounts, useUnlinkGoogle } from '@/hooks';
import { config } from '@/config';
import {
  Loader2,
  Link2,
  Unlink,
  Chrome,
  AlertCircle,
} from 'lucide-react';

export default function LinkedAccountsPage() {
  const { data: accounts, isLoading } = useLinkedAccounts();
  const { mutate: unlinkGoogle, isPending: isUnlinking } = useUnlinkGoogle();

  return (
    <div className="container py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Linked Accounts</h1>
        <p className="text-muted-foreground">
          Manage OAuth accounts linked to your profile
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Google Account */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <Chrome className="h-5 w-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-lg">Google</CardTitle>
                <CardDescription>Sign in with your Google account</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center py-4">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            ) : accounts && accounts.length > 0 ? (
              <div className="space-y-3">
                {accounts.map((account) => (
                  <div
                    key={account.provider}
                    className="flex items-center justify-between rounded-lg border p-3"
                  >
                    <div className="flex items-center gap-3">
                      <Link2 className="h-4 w-4 text-green-500" />
                      <div>
                        <p className="text-sm font-medium capitalize">
                          {account.provider}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {account.email}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="default" className="text-xs">
                        Linked
                      </Badge>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => {
                          if (confirm('Unlink your Google account?')) {
                            unlinkGoogle();
                          }
                        }}
                        disabled={isUnlinking}
                      >
                        {isUnlinking ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Unlink className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-6 text-center">
                <AlertCircle className="mb-2 h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">No linked accounts</p>
                <Button variant="outline" size="sm" className="mt-4 gap-2" asChild>
                  <a href={`${config.api.baseUrl}/auth/google`}>
                    <Chrome className="h-4 w-4" />
                    Link Google Account
                  </a>
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
