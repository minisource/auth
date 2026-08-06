import * as React from 'react';
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  CopyableValue,
  DescriptionList,
  KeyValueItem,
} from '@minisource/ui';
import { Code, Terminal, Server, ShieldCheck, Sparkles } from 'lucide-react';

interface TenantGuideModalProps {
  tenant: { id: string; name: string; slug: string; domain?: string } | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isNew?: boolean;
}

export function TenantGuideModal({ tenant, open, onOpenChange, isNew = false }: TenantGuideModalProps) {
  if (!tenant) return null;

  const curlSnippet = `curl -X GET "https://api.minisource.com/v1/users/me" \\
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \\
  -H "X-Tenant-ID: ${tenant.id}"`;

  const headerSnippet = `// HTTP Request Headers
X-Tenant-ID: ${tenant.id}
X-Tenant-Slug: ${tenant.slug}`;

  const configSnippet = `// Service Configuration (Go / Node.js)
const tenantConfig = {
  tenantId: "${tenant.id}",
  slug: "${tenant.slug}",
  domain: "${tenant.domain || `${tenant.slug}.minisource.com`}"
};`;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[650px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-xl">
            {isNew ? (
              <>
                <Sparkles className="h-5 w-5 text-amber-500" />
                Tenant Created Successfully!
              </>
            ) : (
              <>
                <Code className="h-5 w-5 text-primary" />
                Integration & Developer Guide — {tenant.name}
              </>
            )}
          </DialogTitle>
          <DialogDescription>
            Use these identifiers and code snippets to bind your microservices and OAuth providers to this tenant.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Key Identifiers Card */}
          <div className="rounded-lg border bg-muted/40 p-4">
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Tenant Identifiers
            </h4>
            <DescriptionList cols={2}>
              <KeyValueItem label="Tenant ID" value={<CopyableValue value={tenant.id} />} />
              <KeyValueItem label="Tenant Slug" value={<CopyableValue value={tenant.slug} />} />
            </DescriptionList>
          </div>

          {/* Usage Tabs */}
          <Tabs defaultValue="header" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="header" className="flex items-center gap-1.5 text-xs">
                <Server className="h-3.5 w-3.5" /> HTTP Header
              </TabsTrigger>
              <TabsTrigger value="curl" className="flex items-center gap-1.5 text-xs">
                <Terminal className="h-3.5 w-3.5" /> cURL Request
              </TabsTrigger>
              <TabsTrigger value="config" className="flex items-center gap-1.5 text-xs">
                <ShieldCheck className="h-3.5 w-3.5" /> Service Binding
              </TabsTrigger>
            </TabsList>

            <TabsContent value="header" className="mt-3 space-y-2">
              <p className="text-xs text-muted-foreground">
                Pass the <code>X-Tenant-ID</code> header in all microservice requests (e.g. Notifier, Payment, Gateway) to scope operations to this tenant:
              </p>
              <div className="relative rounded-md bg-zinc-950 p-3 text-xs text-zinc-100 font-mono">
                <pre>{headerSnippet}</pre>
              </div>
            </TabsContent>

            <TabsContent value="curl" className="mt-3 space-y-2">
              <p className="text-xs text-muted-foreground">
                Sample API call verifying user context within this tenant:
              </p>
              <div className="relative rounded-md bg-zinc-950 p-3 text-xs text-zinc-100 font-mono overflow-x-auto">
                <pre>{curlSnippet}</pre>
              </div>
            </TabsContent>

            <TabsContent value="config" className="mt-3 space-y-2">
              <p className="text-xs text-muted-foreground">
                When configuring OAuth Providers, Roles, or Service Clients, assign <code>tenantId</code> to scope them exclusively to this organization:
              </p>
              <div className="relative rounded-md bg-zinc-950 p-3 text-xs text-zinc-100 font-mono">
                <pre>{configSnippet}</pre>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>Got it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
