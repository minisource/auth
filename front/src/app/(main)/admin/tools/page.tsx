'use client';

import { useState } from 'react';
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Separator, Textarea } from '@minisource/ui';
import {
  Wrench,
  Search,
  ShieldCheck,
  Loader2,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

export default function AdminToolsPage() {
  const [tokenInput, setTokenInput] = useState('');
  const [introspecting, setIntrospecting] = useState(false);
  const [introspectResult, setIntrospectResult] = useState<any>(null);

  const handleIntrospect = async () => {
    if (!tokenInput.trim()) return;
    setIntrospecting(true);
    // Backend endpoint: POST /admin/tools/introspect-token
    try {
      const { api } = await import('@/api');
      const result = await api.post('/admin/tools/introspect-token', { token: tokenInput });
      setIntrospectResult(result);
    } catch (err: any) {
      setIntrospectResult({ active: false, error: err.message || 'Introspection failed' });
    } finally {
      setIntrospecting(false);
    }
  };

  const tabs = [
    { id: 'introspect', label: 'Token Introspection', icon: Search },
    { id: 'permissions', label: 'Permission Checker', icon: ShieldCheck },
    { id: 'jwks', label: 'JWKS Status', icon: Wrench },
  ];

  const [activeTool, setActiveTool] = useState('introspect');

  return (
    <div className="container py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Admin Tools</h1>
        <p className="text-muted-foreground">
          Development and diagnostic utilities
        </p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar */}
        <nav className="hidden w-56 shrink-0 space-y-1 md:block">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTool(tab.id)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                activeTool === tab.id
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1 space-y-6">
          {activeTool === 'introspect' && (
            <Card>
              <CardHeader>
                <CardTitle>Token Introspection</CardTitle>
                <CardDescription>Validate and decode any JWT token</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Token</Label>
                  <Textarea
                    placeholder="Paste a JWT token to introspect..."
                    value={tokenInput}
                    onChange={(e) => setTokenInput(e.target.value)}
                    className="font-mono text-xs"
                    rows={4}
                  />
                </div>
                <Button onClick={handleIntrospect} disabled={introspecting || !tokenInput.trim()}>
                  {introspecting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Introspect
                </Button>

                {introspectResult && (
                  <div className="space-y-3 rounded-lg border p-4">
                    <div className="flex items-center gap-2">
                      {introspectResult.active ? (
                        <>
                          <CheckCircle2 className="h-5 w-5 text-green-500" />
                          <span className="font-medium text-green-600 dark:text-green-400">Active Token</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="h-5 w-5 text-red-500" />
                          <span className="font-medium text-red-600 dark:text-red-400">Invalid Token</span>
                        </>
                      )}
                    </div>
                    <Separator />
                    <pre className="overflow-auto rounded bg-muted p-3 text-xs">
                      {JSON.stringify(introspectResult, null, 2)}
                    </pre>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {activeTool === 'permissions' && (
            <Card>
              <CardHeader>
                <CardTitle>Permission Checker</CardTitle>
                <CardDescription>Check if a role has a specific permission</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Role Name</Label>
                    <Input placeholder="e.g. admin" />
                  </div>
                  <div className="space-y-2">
                    <Label>Permission</Label>
                    <Input placeholder="e.g. users:create" />
                  </div>
                </div>
                <Button disabled>Check Permission</Button>
                <p className="text-xs text-muted-foreground">
                  Backend endpoint ready: <code className="rounded bg-muted px-1">POST /admin/tools/check-permission</code>
                </p>
              </CardContent>
            </Card>
          )}

          {activeTool === 'jwks' && (
            <Card>
              <CardHeader>
                <CardTitle>JWKS Status</CardTitle>
                <CardDescription>View current JWT key configuration</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Public JWKS Endpoint</Label>
                  <code className="block rounded bg-muted p-2 text-sm">
                    http://127.0.0.1:9001/v1/.well-known/jwks.json
                  </code>
                </div>
                <div className="space-y-2">
                  <Label>Issuer</Label>
                  <code className="block rounded bg-muted p-2 text-sm">minisource-auth</code>
                </div>
                <Button disabled>Check JWKS Status</Button>
                <p className="text-xs text-muted-foreground">
                  Backend endpoint ready: <code className="rounded bg-muted px-1">GET /admin/tools/jwks-status</code>
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
