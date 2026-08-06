'use client';

import { useState } from 'react';
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } from '@minisource/ui';
import { api, apiClient } from '@/api';
import { Loader2, Server, CheckCircle2, Copy, Eye, EyeOff } from 'lucide-react';

export default function ServiceAuthPage() {
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleAuth = async () => {
    if (!clientId.trim() || !clientSecret.trim()) return;
    setIsLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await api.post('/service/auth', {
        clientId,
        clientSecret,
      });
      setResult(response as Record<string, unknown>);
    } catch (err: unknown) {
      const apiError = err as { message?: string };
      setError(apiError?.message || 'Authentication failed');
    }
    setIsLoading(false);
  };

  const handleValidate = async () => {
    if (!result) return;
    const token = (result as { accessToken?: string }).accessToken;
    if (!token) return;
    setIsLoading(true);
    setError('');
    try {
      const response = await apiClient.get('/service/validate', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setResult({
        ...result,
        validation: response.data,
      });
    } catch (err: unknown) {
      const apiError = err as { message?: string };
      setError(apiError?.message || 'Validation failed');
    }
    setIsLoading(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="container py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Service Authentication</h1>
        <p className="text-muted-foreground">
          Test service-to-service authentication with OAuth2 client credentials
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Client Credentials</CardTitle>
            <CardDescription>
              Enter your service client ID and secret to get an access token
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="clientId">Client ID</Label>
              <Input
                id="clientId"
                placeholder="e.g. auth-service"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Try: auth-service, gateway-service, notifier-service
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="clientSecret">Client Secret</Label>
              <div className="relative">
                <Input
                  id="clientSecret"
                  type={showSecret ? 'text' : 'password'}
                  placeholder="Service client secret"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  className="pr-10"
                />
                <Button
                  variant="ghost"
                  size="icon"
                  className="absolute right-1 top-1/2 -translate-y-1/2"
                  onClick={() => setShowSecret(!showSecret)}
                >
                  {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>
            <Button
              onClick={handleAuth}
              disabled={!clientId.trim() || !clientSecret.trim() || isLoading}
              className="w-full gap-2"
            >
              {isLoading && !result ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Server className="h-4 w-4" />
              )}
              Authenticate
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Result</CardTitle>
            <CardDescription>
              {result ? 'Service authenticated' : 'No result yet'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {result ? (
              <>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  <span className="font-medium text-green-600">
                    Authentication successful
                  </span>
                </div>

                <div className="rounded-lg bg-muted p-4">
                  <pre className="overflow-x-auto text-xs">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>

                {(result as { accessToken?: string }).accessToken && (
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-2"
                      onClick={() =>
                        copyToClipboard(
                          (result as { accessToken?: string }).accessToken || ''
                        )
                      }
                    >
                      <Copy className="h-4 w-4" />
                      Copy Token
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      className="gap-2"
                      onClick={handleValidate}
                      disabled={isLoading}
                    >
                      {isLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4" />
                      )}
                      Validate Token
                    </Button>
                  </div>
                )}

                {(result as { validation?: Record<string, unknown> }).validation && (
                  <div className="rounded-lg border border-green-200 bg-green-50 p-3 dark:border-green-900 dark:bg-green-950">
                    <p className="mb-2 text-sm font-medium text-green-700 dark:text-green-400">
                      Validation Result
                    </p>
                    <pre className="overflow-x-auto text-xs">
                      {JSON.stringify(
                        (result as { validation?: Record<string, unknown> }).validation,
                        null,
                        2
                      )}
                    </pre>
                  </div>
                )}
              </>
            ) : error ? (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <p className="text-sm text-destructive">{error}</p>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Server className="mb-2 h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  Enter client credentials to authenticate
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
