'use client';

import { useState } from 'react';
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Label, Textarea } from '@minisource/ui';
import { apiClient } from '@/api';
import { Loader2, ShieldCheck, ShieldX, Eye, EyeOff } from 'lucide-react';

export default function ValidateTokenPage() {
  const [token, setToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleValidate = async () => {
    if (!token.trim()) return;
    setIsLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await apiClient.get('/tokens/validate', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setResult(response.data as Record<string, unknown>);
    } catch (err: unknown) {
      const apiError = err as { message?: string };
      setError(apiError?.message || 'Token validation failed');
    }
    setIsLoading(false);
  };

  const isValid = result && (result as { valid?: boolean }).valid;

  return (
    <div className="container py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Validate Token</h1>
        <p className="text-muted-foreground">
          Debug tool to validate user and service bearer tokens
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Token Input</CardTitle>
            <CardDescription>
              Paste a JWT token to validate against the auth service
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="token">Bearer Token</Label>
              <div className="relative">
                <Textarea
                  id="token"
                  placeholder="Paste your JWT token here..."
                  className="min-h-[100px] font-mono text-xs"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
                <Button
                  variant="ghost"
                  size="icon"
                  className="absolute right-2 top-2"
                  onClick={() => setShowToken(!showToken)}
                >
                  {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>
            <Button
              onClick={handleValidate}
              disabled={!token.trim() || isLoading}
              className="w-full gap-2"
            >
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
              Validate Token
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Validation Result</CardTitle>
            <CardDescription>
              {result
                ? 'Token validation completed'
                : 'Submit a token to see results'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : result ? (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  {isValid ? (
                    <>
                      <ShieldCheck className="h-5 w-5 text-green-500" />
                      <span className="font-medium text-green-600">Valid Token</span>
                    </>
                  ) : (
                    <>
                      <ShieldX className="h-5 w-5 text-red-500" />
                      <span className="font-medium text-red-600">Invalid Token</span>
                    </>
                  )}
                </div>

                <div className="rounded-lg bg-muted p-4">
                  <pre className="overflow-x-auto text-xs">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>

                {(result as { tokenType?: string }).tokenType && (
                  <Badge variant="outline">
                    Type: {(result as { tokenType?: string }).tokenType}
                  </Badge>
                )}
                {(result as { scopes?: string[] }).scopes && (
                  <div className="flex flex-wrap gap-1">
                    {(result as { scopes?: string[] }).scopes?.map((scope) => (
                      <Badge key={scope} variant="secondary" className="text-xs">
                        {scope}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            ) : error ? (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <ShieldX className="mb-2 h-8 w-8 text-destructive" />
                <p className="text-sm text-destructive">{error}</p>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <ShieldCheck className="mb-2 h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  Enter a token and click validate
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
