'use client';

import { useState, useEffect } from 'react';
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Separator, Switch, PageHeader, ServiceStatus } from '@minisource/ui';
import {
  Lock,
  Smartphone,
  Globe,
  Shield,
  Gauge,
  ArrowLeftRight,
  Loader2,
  Bell,
} from 'lucide-react';
import { useAdminSettings, useUpdateAdminSettings } from '@/hooks';

export default function AdminSettingsPage() {
  const [activeTab, setActiveTab] = useState('password');
  const { data: settings, isLoading, error } = useAdminSettings();
  const { mutate: updateSettings, isPending: isSaving } = useUpdateAdminSettings();

  const categories = [
    { id: 'password', label: 'Password Policy', icon: Lock },
    { id: 'otp', label: 'OTP Settings', icon: Smartphone },
    { id: 'notifier', label: 'Notifier Integration', icon: Bell },
    { id: 'oauth', label: 'OAuth / Google', icon: Globe },
    { id: 'security', label: 'Login & Security', icon: Shield },
    { id: 'rate-limit', label: 'Rate Limiting', icon: Gauge },
    { id: 'cors', label: 'CORS', icon: ArrowLeftRight },
  ];

  const getSetting = (key: string): string => {
    if (!settings) return '';
    for (const category in settings) {
      const setting = (settings as any)[category]?.find((s: any) => s.key === key);
      if (setting) return setting.value;
    }
    return '';
  };

  const handleSave = (updates: Record<string, string>) => {
    updateSettings(updates);
  };

  return (
    <div className="container py-8">
      <PageHeader
        title="System Settings"
        description="Configure authentication, security, and system settings"
      />

      {error && (
        <Card className="mb-6 border-destructive/50">
          <CardContent className="pt-6">
            <p className="text-sm text-destructive">
              Failed to load settings: {(error as any)?.message || 'Unknown error'}
            </p>
          </CardContent>
        </Card>
      )}

      <div className="flex gap-6">
        <nav className="hidden w-56 shrink-0 space-y-1 md:block">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setActiveTab(cat.id)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                activeTab === cat.id
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              }`}
            >
              <cat.icon className="h-4 w-4" />
              {cat.label}
            </button>
          ))}
        </nav>

        <div className="flex-1">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : activeTab === 'password' ? (
            <PasswordSettings defaultValues={{ minLength: getSetting('password_min_length') || '8', requireUppercase: getSetting('password_require_uppercase') !== 'false', requireLowercase: getSetting('password_require_lowercase') !== 'false', requireNumber: getSetting('password_require_number') !== 'false', requireSpecial: getSetting('password_require_special') === 'true' }} onSave={handleSave} saving={isSaving} />
          ) : activeTab === 'otp' ? (
            <OTPSettings defaultValues={{ length: getSetting('otp_length') || '6', expiry: getSetting('otp_expiry_minutes') || '5', maxAttempts: getSetting('otp_max_attempts') || '5', enabled: getSetting('enable_otp_login') !== 'false' }} onSave={handleSave} saving={isSaving} />
          ) : activeTab === 'notifier' ? (
            <NotifierSettings defaultValues={{ enabled: getSetting('notifier_enabled') !== 'false', httpUrl: getSetting('notifier_http_url') || 'http://localhost:9002', grpcAddress: getSetting('notifier_grpc_address') || 'localhost:9003', clientId: getSetting('notifier_client_id') || 'auth-service' }} onSave={handleSave} saving={isSaving} />
          ) : activeTab === 'oauth' ? (
            <OAuthSettings defaultValues={{ enabled: getSetting('enable_google_login') !== 'false', clientId: getSetting('google_client_id') || '', redirectUrl: getSetting('google_redirect_url') || 'http://localhost:9001/api/v1/auth/google/callback', mockEnabled: getSetting('google_mock_enabled') === 'true' }} onSave={handleSave} saving={isSaving} />
          ) : activeTab === 'security' ? (
            <SecuritySettings defaultValues={{ maxAttempts: getSetting('max_login_attempts') || '5', lockDuration: getSetting('lock_duration_minutes') || '30', sessionTtl: getSetting('session_timeout_minutes') || '15', requireEmailVerify: getSetting('require_email_verification') === 'true', allowRegistration: getSetting('allow_registration') !== 'false' }} onSave={handleSave} saving={isSaving} />
          ) : activeTab === 'rate-limit' ? (
            <RateLimitSettings defaultValues={{ login: getSetting('auth_login_rate_limit') || '5', register: getSetting('auth_register_rate_limit') || '3', otp: getSetting('auth_otp_rate_limit') || '3', passwordReset: getSetting('auth_password_reset_rate_limit') || '5' }} onSave={handleSave} saving={isSaving} />
          ) : activeTab === 'cors' ? (
            <CORSSettings defaultValues={{ origins: getSetting('cors_allowed_origins') || '*', methods: getSetting('cors_allowed_methods') || 'GET,POST,PUT,PATCH,DELETE,OPTIONS', headers: getSetting('cors_allowed_headers') || 'Origin,Content-Type,Accept,Authorization,X-Tenant-ID' }} onSave={handleSave} saving={isSaving} />
          ) : null}
        </div>
      </div>
    </div>
  );
}

// Sub-components for each settings category
function PasswordSettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [minLength, setMinLength] = useState(defaultValues.minLength);
  const [requireUppercase, setRequireUppercase] = useState(defaultValues.requireUppercase);
  const [requireLowercase, setRequireLowercase] = useState(defaultValues.requireLowercase);
  const [requireNumber, setRequireNumber] = useState(defaultValues.requireNumber);
  const [requireSpecial, setRequireSpecial] = useState(defaultValues.requireSpecial);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Password Policy</CardTitle>
        <CardDescription>Configure password strength requirements</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Minimum Length</Label>
          <Input type="number" value={minLength} onChange={(e) => setMinLength(e.target.value)} className="w-32" />
        </div>
        <Separator />
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div><Label>Require Uppercase</Label><p className="text-xs text-muted-foreground">At least one uppercase letter (A-Z)</p></div>
            <Switch checked={requireUppercase} onCheckedChange={setRequireUppercase} />
          </div>
          <div className="flex items-center justify-between">
            <div><Label>Require Lowercase</Label><p className="text-xs text-muted-foreground">At least one lowercase letter (a-z)</p></div>
            <Switch checked={requireLowercase} onCheckedChange={setRequireLowercase} />
          </div>
          <div className="flex items-center justify-between">
            <div><Label>Require Number</Label><p className="text-xs text-muted-foreground">At least one number (0-9)</p></div>
            <Switch checked={requireNumber} onCheckedChange={setRequireNumber} />
          </div>
          <div className="flex items-center justify-between">
            <div><Label>Require Special Character</Label><p className="text-xs text-muted-foreground">At least one special character (!@#$%)</p></div>
            <Switch checked={requireSpecial} onCheckedChange={setRequireSpecial} />
          </div>
        </div>
        <Button onClick={() => onSave({ password_min_length: minLength, password_require_uppercase: String(requireUppercase), password_require_lowercase: String(requireLowercase), password_require_number: String(requireNumber), password_require_special: String(requireSpecial) })} disabled={saving}>
          {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save Password Settings
        </Button>
      </CardContent>
    </Card>
  );
}

function OTPSettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [length, setLength] = useState(defaultValues.length);
  const [expiry, setExpiry] = useState(defaultValues.expiry);
  const [maxAttempts, setMaxAttempts] = useState(defaultValues.maxAttempts);
  const [enabled, setEnabled] = useState(defaultValues.enabled);

  return (
    <Card>
      <CardHeader><CardTitle>OTP Settings</CardTitle><CardDescription>Configure one-time password settings</CardDescription></CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2"><Label>OTP Length</Label><Input type="number" value={length} onChange={(e) => setLength(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>OTP Expiry (minutes)</Label><Input type="number" value={expiry} onChange={(e) => setExpiry(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>Max Attempts</Label><Input type="number" value={maxAttempts} onChange={(e) => setMaxAttempts(e.target.value)} className="w-24" /></div>
        </div>
        <Separator />
        <div className="flex items-center justify-between">
          <div><Label>Enable OTP Login</Label><p className="text-xs text-muted-foreground">Allow users to login via phone OTP</p></div>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <Button onClick={() => onSave({ otp_length: length, otp_expiry_minutes: expiry, otp_max_attempts: maxAttempts, enable_otp_login: String(enabled) })} disabled={saving}>
          {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save OTP Settings
        </Button>
      </CardContent>
    </Card>
  );
}

function OAuthSettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [enabled, setEnabled] = useState(defaultValues.enabled);
  const [clientId, setClientId] = useState(defaultValues.clientId);
  const [clientSecret, setClientSecret] = useState('');
  const [redirectUrl, setRedirectUrl] = useState(defaultValues.redirectUrl);
  const [mockEnabled, setMockEnabled] = useState(defaultValues.mockEnabled);

  return (
    <Card>
      <CardHeader><CardTitle>OAuth / Google</CardTitle><CardDescription>Configure Google OAuth integration</CardDescription></CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <div><Label>Enable Google OAuth</Label><p className="text-xs text-muted-foreground">Allow users to login with Google</p></div>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <Separator />
        <div className="space-y-2">
          <Label>Client ID</Label>
          <Input value={clientId} onChange={(e) => setClientId(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Client Secret (write-only)</Label>
          <Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder="Enter new secret to update" />
        </div>
        <div className="space-y-2">
          <Label>Redirect URL</Label>
          <Input value={redirectUrl} onChange={(e) => setRedirectUrl(e.target.value)} />
        </div>
        <div className="flex items-center justify-between">
          <div><Label>Mock Mode (Dev Only)</Label><p className="text-xs text-muted-foreground">Use mock credentials for development</p></div>
          <Switch checked={mockEnabled} onCheckedChange={setMockEnabled} />
        </div>
        <Button onClick={() => {
          const updates: Record<string, string> = {
            enable_google_login: String(enabled),
            google_client_id: clientId,
            google_redirect_url: redirectUrl,
            google_mock_enabled: String(mockEnabled),
          };
          if (clientSecret) updates.google_client_secret = clientSecret;
          onSave(updates);
        }} disabled={saving}>
          {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save OAuth Settings
        </Button>
      </CardContent>
    </Card>
  );
}

function SecuritySettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [maxAttempts, setMaxAttempts] = useState(defaultValues.maxAttempts);
  const [lockDuration, setLockDuration] = useState(defaultValues.lockDuration);
  const [sessionTtl, setSessionTtl] = useState(defaultValues.sessionTtl);
  const [requireEmailVerify, setRequireEmailVerify] = useState(defaultValues.requireEmailVerify);
  const [allowRegistration, setAllowRegistration] = useState(defaultValues.allowRegistration);

  return (
    <Card>
      <CardHeader><CardTitle>Login & Security</CardTitle><CardDescription>Configure login policies and security settings</CardDescription></CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2"><Label>Max Failed Attempts</Label><Input type="number" value={maxAttempts} onChange={(e) => setMaxAttempts(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>Lock Duration (minutes)</Label><Input type="number" value={lockDuration} onChange={(e) => setLockDuration(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>Session TTL (minutes)</Label><Input type="number" value={sessionTtl} onChange={(e) => setSessionTtl(e.target.value)} className="w-24" /></div>
        </div>
        <Separator />
        <div className="flex items-center justify-between">
          <div><Label>Require Email Verification</Label><p className="text-xs text-muted-foreground">Users must verify email</p></div>
          <Switch checked={requireEmailVerify} onCheckedChange={setRequireEmailVerify} />
        </div>
        <div className="flex items-center justify-between">
          <div><Label>Allow Registration</Label><p className="text-xs text-muted-foreground">Allow new users to register</p></div>
          <Switch checked={allowRegistration} onCheckedChange={setAllowRegistration} />
        </div>
        <Button onClick={() => onSave({ max_login_attempts: maxAttempts, lock_duration_minutes: lockDuration, session_timeout_minutes: sessionTtl, require_email_verification: String(requireEmailVerify), allow_registration: String(allowRegistration) })} disabled={saving}>
          {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save Security Settings
        </Button>
      </CardContent>
    </Card>
  );
}

function RateLimitSettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [login, setLogin] = useState(defaultValues.login);
  const [register, setRegister] = useState(defaultValues.register);
  const [otp, setOtp] = useState(defaultValues.otp);
  const [passwordReset, setPasswordReset] = useState(defaultValues.passwordReset);

  return (
    <Card>
      <CardHeader><CardTitle>Rate Limiting</CardTitle><CardDescription>Configure API rate limits (set to 0 to disable)</CardDescription></CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2"><Label>Login (per minute)</Label><Input type="number" value={login} onChange={(e) => setLogin(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>Register (per minute)</Label><Input type="number" value={register} onChange={(e) => setRegister(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>OTP Send (per minute)</Label><Input type="number" value={otp} onChange={(e) => setOtp(e.target.value)} className="w-24" /></div>
          <div className="space-y-2"><Label>Password Reset (per hour)</Label><Input type="number" value={passwordReset} onChange={(e) => setPasswordReset(e.target.value)} className="w-24" /></div>
        </div>
        <Button onClick={() => onSave({ auth_login_rate_limit: login, auth_register_rate_limit: register, auth_otp_rate_limit: otp, auth_password_reset_rate_limit: passwordReset })} disabled={saving}>
          {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save Rate Limit Settings
        </Button>
      </CardContent>
    </Card>
  );
}

function CORSSettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [origins, setOrigins] = useState(defaultValues.origins);
  const [methods, setMethods] = useState(defaultValues.methods);
  const [headers, setHeaders] = useState(defaultValues.headers);

  return (
    <Card>
      <CardHeader><CardTitle>CORS Configuration</CardTitle><CardDescription>Configure cross-origin resource sharing</CardDescription></CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2"><Label>Allowed Origins</Label><Input value={origins} onChange={(e) => setOrigins(e.target.value)} /></div>
        <div className="space-y-2"><Label>Allowed Methods</Label><Input value={methods} onChange={(e) => setMethods(e.target.value)} /></div>
        <div className="space-y-2"><Label>Allowed Headers</Label><Input value={headers} onChange={(e) => setHeaders(e.target.value)} /></div>
        <Button onClick={() => onSave({ cors_allowed_origins: origins, cors_allowed_methods: methods, cors_allowed_headers: headers })} disabled={saving}>
          {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save CORS Settings
        </Button>
      </CardContent>
    </Card>
  );
}

function NotifierSettings({ defaultValues, onSave, saving }: { defaultValues: Record<string, any>; onSave: (updates: Record<string, string>) => void; saving: boolean }) {
  const [enabled, setEnabled] = useState(defaultValues.enabled);
  const [httpUrl, setHttpUrl] = useState(defaultValues.httpUrl || 'http://localhost:9002');
  const [grpcAddress, setGrpcAddress] = useState(defaultValues.grpcAddress || 'localhost:9003');
  const [clientId, setClientId] = useState(defaultValues.clientId || 'auth-service');

  const [healthStatus, setHealthStatus] = useState<'operational' | 'degraded' | 'unavailable' | 'unknown'>('unknown');
  const [lastChecked, setLastChecked] = useState<string>('');
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);

  const checkNotifierHealth = async () => {
    setIsCheckingHealth(true);
    try {
      const { api } = await import('@/api');
      const res: any = await api.get('/admin/tools/notifier-health');
      if (res?.status === 'operational') {
        setHealthStatus('operational');
      } else if (res?.status === 'degraded') {
        setHealthStatus('degraded');
      } else {
        setHealthStatus('unavailable');
      }
      setLastChecked(new Date().toLocaleTimeString());
    } catch {
      setHealthStatus('unavailable');
      setLastChecked(new Date().toLocaleTimeString());
    } finally {
      setIsCheckingHealth(false);
    }
  };

  useEffect(() => {
    checkNotifierHealth();
  }, []);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Notifier Microservice Health</CardTitle>
          <CardDescription>Live health check status of the Notifier microservice</CardDescription>
        </CardHeader>
        <CardContent>
          <ServiceStatus
            serviceName="Notifier Microservice (SMS / Email / Push)"
            status={healthStatus}
            lastCheckedAt={lastChecked ? `Last checked: ${lastChecked}` : undefined}
            onCheckStatus={checkNotifierHealth}
            isChecking={isCheckingHealth}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Notifier Integration Settings</CardTitle>
          <CardDescription>Configure connection details and toggle integration with the Notifier service</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label className="text-base">Enable Notifier Integration</Label>
              <p className="text-xs text-muted-foreground">Send OTPs and transactional notifications via Notifier service</p>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
          <Separator />
          <div className="space-y-2">
            <Label>Notifier HTTP URL (Optional)</Label>
            <Input value={httpUrl} onChange={(e) => setHttpUrl(e.target.value)} placeholder="http://localhost:9002" />
            <p className="text-xs text-muted-foreground">HTTP API endpoint for sending SMS/Email notifications</p>
          </div>
          <div className="space-y-2">
            <Label>Notifier gRPC Address (Optional)</Label>
            <Input value={grpcAddress} onChange={(e) => setGrpcAddress(e.target.value)} placeholder="localhost:9003" />
            <p className="text-xs text-muted-foreground">High-performance gRPC endpoint for async notification delivery</p>
          </div>
          <div className="space-y-2">
            <Label>Notifier Service Client ID</Label>
            <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="auth-service" />
          </div>
          <Button
            onClick={() =>
              onSave({
                notifier_enabled: enabled ? 'true' : 'false',
                notifier_http_url: httpUrl,
                notifier_grpc_address: grpcAddress,
                notifier_client_id: clientId,
              })
            }
            disabled={saving}
          >
            {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Save Notifier Settings
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
