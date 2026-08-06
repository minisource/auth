'use client';

import React, { useState } from 'react';
import { useAuthStore } from '@/stores';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
  Button,
  Input,
  Label,
  Badge,
} from '@minisource/ui';
import {
  Wrench,
  Play,
  RotateCcw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  History,
  Copy,
  Lock,
  Send,
  UserCheck,
  Heart,
  Eye,
  EyeOff,
  Activity,
  Check,
} from 'lucide-react';
import { toast } from 'sonner';

interface ExecutionStep {
  number: number;
  title: string;
  state: 'idle' | 'running' | 'success' | 'failed';
  method?: string;
  url?: string;
  statusCode?: number;
  duration?: number;
  requestId?: string;
  correlationId?: string;
  responseBody?: any;
}

interface ExecutionHistoryItem {
  id: string;
  timestamp: string;
  operationId: string;
  success: boolean;
  statusCode: number;
  duration: number;
  request: any;
  response: any;
}

export default function ApiLabPage() {
  const { tokens } = useAuthStore();
  const [activeTab, setActiveTab] = useState<'overview' | 'otp' | 'session' | 'token' | 'health' | 'permissions'>('overview');

  // Request Configuration State
  const [authMode, setAuthMode] = useState<'current-session' | 'bearer-token' | 'none'>('current-session');
  const [customToken, setCustomToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [customHeaders, setCustomHeaders] = useState<Array<{ key: string; value: string }>>([
    { key: 'X-Correlation-ID', value: `corr-${Math.random().toString(36).substring(2, 9)}` },
  ]);

  // History State
  const [history, setHistory] = useState<ExecutionHistoryItem[]>([]);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<ExecutionHistoryItem | null>(null);

  // OTP Scenario State
  const [otpType, setOtpType] = useState('phone'); // phone or email
  const [otpDestination, setOtpDestination] = useState('');
  const [otpPurpose, setOtpPurpose] = useState('login'); // login, verify-email, reset-password
  const [otpCode, setOtpCode] = useState('');
  const [otpSteps, setOtpSteps] = useState<ExecutionStep[]>([
    { number: 1, title: 'Request OTP', state: 'idle' },
    { number: 2, title: 'Verify OTP Code', state: 'idle' },
    { number: 3, title: 'Fetch Profile with Session Token', state: 'idle' },
  ]);
  const [sessionTokenChained, setSessionTokenChained] = useState('');

  // Token Introspection Scenario State
  const [tokenToValidate, setTokenToValidate] = useState('');
  const [introspectionApi, setIntrospectionApi] = useState<'auth' | 'admin'>('auth');

  // Health Diagnostics Scenario State
  const [healthTarget, setHealthTarget] = useState<'system' | 'ready' | 'tools' | 'jwks'>('system');

  // Permission Diagnostics State
  const [permissionUserId, setPermissionUserId] = useState('');
  const [permissionKey, setPermissionKey] = useState('');
  const [permissionTenantId, setPermissionTenantId] = useState('');

  // General Scenario Execution Loading State
  const [executing, setExecuting] = useState(false);
  const [diagnosticResult, setDiagnosticResult] = useState<any>(null);

  // Load execution history from memory-session
  const addHistoryItem = (item: Omit<ExecutionHistoryItem, 'id' | 'timestamp'>) => {
    const newItem: ExecutionHistoryItem = {
      ...item,
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toLocaleTimeString(),
    };
    setHistory((prev) => [newItem, ...prev]);
    setSelectedHistoryItem(newItem);
  };

  const handleCopy = (text: string, label: string) => {
    if (typeof navigator !== 'undefined') {
      navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text);
      toast.success(`${label} copied to clipboard!`);
    }
  };

  // ─── Execute Helper ───
  const executeOperation = async (operationId: string, input: any) => {
    setExecuting(true);
    try {
      const headersToSend: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (tokens?.accessToken) {
        headersToSend['Authorization'] = `Bearer ${tokens.accessToken}`;
      }

      // Format custom headers map
      const headersMap: Record<string, string> = {};
      customHeaders.forEach((h) => {
        if (h.key.trim() && h.value.trim()) {
          headersMap[h.key] = h.value;
        }
      });

      const response = await fetch('/api/admin/api-lab/execute', {
        method: 'POST',
        headers: headersToSend,
        body: JSON.stringify({
          operationId,
          input,
          authMode,
          customToken: authMode === 'bearer-token' ? customToken : undefined,
          headers: headersMap,
        }),
      });

      const result = await response.json();
      setDiagnosticResult(result);
      addHistoryItem({
        operationId,
        success: result.success,
        statusCode: result.statusCode,
        duration: result.duration,
        request: result.request,
        response: result.response,
      });

      return result;
    } catch (err: any) {
      toast.error(err.message || 'Execution request failed');
      return null;
    } finally {
      setExecuting(false);
    }
  };

  // ─── Scenario: OTP ───
  const handleOTPRequest = async () => {
    if (!otpDestination) {
      toast.error('Destination address/phone is required');
      return;
    }

    setOtpSteps([
      { number: 1, title: 'Request OTP', state: 'running' },
      { number: 2, title: 'Verify OTP Code', state: 'idle' },
      { number: 3, title: 'Fetch Profile with Session Token', state: 'idle' },
    ]);

    const result = await executeOperation('auth.otp.send', {
      email: otpType === 'email' ? otpDestination : undefined,
      phone: otpType === 'phone' ? otpDestination : undefined,
      purpose: otpPurpose,
    });

    if (result && result.success) {
      setOtpSteps([
        {
          number: 1,
          title: 'Request OTP',
          state: 'success',
          method: result.request.method,
          url: result.request.url,
          statusCode: result.statusCode,
          duration: result.duration,
          requestId: result.requestId,
          correlationId: result.correlationId,
        },
        { number: 2, title: 'Verify OTP Code', state: 'idle' },
        { number: 3, title: 'Fetch Profile with Session Token', state: 'idle' },
      ]);
      toast.success('OTP sent successfully through real channels!');
    } else {
      setOtpSteps([
        {
          number: 1,
          title: 'Request OTP',
          state: 'failed',
          statusCode: result?.statusCode || 500,
          duration: result?.duration || 0,
        },
        { number: 2, title: 'Verify OTP Code', state: 'idle' },
        { number: 3, title: 'Fetch Profile with Session Token', state: 'idle' },
      ]);
    }
  };

  const handleOTPVerify = async () => {
    if (!otpCode) {
      toast.error('Verification code is required');
      return;
    }

    setOtpSteps((prev) => [
      prev[0],
      { ...prev[1], state: 'running' },
      prev[2],
    ]);

    const result = await executeOperation('auth.otp.verify', {
      email: otpType === 'email' ? otpDestination : undefined,
      phone: otpType === 'phone' ? otpDestination : undefined,
      code: otpCode,
      purpose: otpPurpose,
    });

    if (result && result.success) {
      const token = result.response?.body?.accessToken || result.response?.body?.token || '';
      setSessionTokenChained(token);

      setOtpSteps((prev) => [
        prev[0],
        {
          number: 2,
          title: 'Verify OTP Code',
          state: 'success',
          method: result.request.method,
          url: result.request.url,
          statusCode: result.statusCode,
          duration: result.duration,
          requestId: result.requestId,
          correlationId: result.correlationId,
        },
        { number: 3, title: 'Fetch Profile with Session Token', state: 'idle' },
      ]);
      toast.success('OTP verified successfully!');
    } else {
      setOtpSteps((prev) => [
        prev[0],
        {
          number: 2,
          title: 'Verify OTP Code',
          state: 'failed',
          statusCode: result?.statusCode || 500,
          duration: result?.duration || 0,
        },
        prev[2],
      ]);
    }
  };

  const handleOTPFollowUp = async () => {
    if (!sessionTokenChained) {
      toast.error('No session token available from Step 2');
      return;
    }

    setOtpSteps((prev) => [
      prev[0],
      prev[1],
      { ...prev[2], state: 'running' },
    ]);

    const oldAuthMode = authMode;
    const oldCustomToken = customToken;

    setAuthMode('bearer-token');
    setCustomToken(sessionTokenChained);

    const result = await executeOperation('users.me', {});

    setAuthMode(oldAuthMode);
    setCustomToken(oldCustomToken);

    if (result && result.success) {
      setOtpSteps((prev) => [
        prev[0],
        prev[1],
        {
          number: 3,
          title: 'Fetch Profile with Session Token',
          state: 'success',
          method: result.request.method,
          url: result.request.url,
          statusCode: result.statusCode,
          duration: result.duration,
          requestId: result.requestId,
          correlationId: result.correlationId,
        },
      ]);
      toast.success('Successfully retrieved profile using OTP session token!');
    } else {
      setOtpSteps((prev) => [
        prev[0],
        prev[1],
        {
          number: 3,
          title: 'Fetch Profile with Session Token',
          state: 'failed',
          statusCode: result?.statusCode || 500,
          duration: result?.duration || 0,
        },
      ]);
    }
  };

  // ─── Scenario: Current Session ───
  const handleFetchSession = async () => {
    await executeOperation('users.me', {});
  };

  // ─── Scenario: Token Validation ───
  const handleValidateToken = async () => {
    if (!tokenToValidate) {
      toast.error('Token is required');
      return;
    }

    if (introspectionApi === 'auth') {
      await executeOperation('auth.introspect', { token: tokenToValidate });
    } else {
      await executeOperation('admin.tools.introspect', { token: tokenToValidate });
    }
  };

  // ─── Scenario: Health ───
  const handleFetchHealth = async () => {
    if (healthTarget === 'system') {
      await executeOperation('admin.health', {});
    } else if (healthTarget === 'ready') {
      await executeOperation('admin.ready', {});
    } else if (healthTarget === 'tools') {
      await executeOperation('admin.tools.health', {});
    } else if (healthTarget === 'jwks') {
      await executeOperation('admin.tools.jwks-status', {});
    }
  };

  // ─── Scenario: Permissions Check ───
  const handleCheckPermission = async () => {
    if (!permissionUserId || !permissionKey) {
      toast.error('User ID and Permission Key are required');
      return;
    }
    await executeOperation('admin.tools.check-permission', {
      userId: permissionUserId,
      permissionKey,
      tenantId: permissionTenantId || undefined,
    });
  };

  return (
    <div className="w-full max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-8">
      {/* Header and Info Bar */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between border-b pb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Wrench className="h-6 w-6 text-primary" /> API Test Lab
          </h1>
          <p className="text-muted-foreground mt-1">
            Production-available diagnostics playground for authorized administrators. All requests are logged in the audit history.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="px-3 py-1 bg-yellow-500/10 border-yellow-500/20 text-yellow-700 dark:text-yellow-400 flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" /> Admin Authorized Area
          </Badge>
          <Badge variant="default" className="px-3 py-1 bg-green-600">
            Active: Production Ready
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Side: Scenarios and Configuration */}
        <div className="lg:col-span-8 space-y-6">
          {/* Tabs header */}
          <div className="flex border-b border-muted gap-2 overflow-x-auto pb-px">
            {['overview', 'otp', 'session', 'token', 'health', 'permissions'].map((tab) => (
              <button
                key={tab}
                onClick={() => { setActiveTab(tab as any); setDiagnosticResult(null); }}
                className={`pb-2.5 px-4 text-sm font-medium border-b-2 transition-colors capitalize whitespace-nowrap ${
                  activeTab === tab ? 'border-primary text-primary font-bold' : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                {tab === 'otp' ? 'OTP Flows' : tab === 'session' ? 'Session info' : tab}
              </button>
            ))}
          </div>

          {/* Configuration Card */}
          <Card className="border border-muted bg-card/50 backdrop-blur-sm">
            <CardHeader className="py-4">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Lock className="h-4 w-4 text-muted-foreground" /> Authentication & Header Request Settings
              </CardTitle>
              <CardDescription>Configure credentials to use for executing the APIs.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 pt-0">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Authentication Mode</Label>
                  <select
                    value={authMode}
                    onChange={(e) => setAuthMode(e.target.value as any)}
                    className="w-full h-10 px-3 rounded-lg border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  >
                    <option value="current-session">Current Admin Session Token</option>
                    <option value="bearer-token">Temporary Bearer Token Override</option>
                    <option value="none">No Authentication (Public API)</option>
                  </select>
                </div>

                {authMode === 'bearer-token' && (
                  <div className="space-y-2">
                    <Label>Temporary Bearer Token</Label>
                    <div className="relative">
                      <Input
                        type={showToken ? 'text' : 'password'}
                        value={customToken}
                        onChange={(e) => setCustomToken(e.target.value)}
                        placeholder="eyJhbGciOi..."
                        className="pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowToken(!showToken)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Custom permitted headers builder */}
              <div className="space-y-2 pt-2 border-t border-muted">
                <div className="flex items-center justify-between">
                  <Label className="text-xs font-semibold uppercase text-muted-foreground">Permitted Diagnostic Headers</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs h-7 px-2"
                    onClick={() => setCustomHeaders((prev) => [...prev, { key: '', value: '' }])}
                  >
                    + Add Header
                  </Button>
                </div>
                <div className="space-y-2">
                  {customHeaders.map((header, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <Input
                        placeholder="Header Key (e.g. X-Correlation-ID)"
                        value={header.key}
                        onChange={(e) => {
                          const val = e.target.value;
                          setCustomHeaders((prev) => {
                            const copy = [...prev];
                            copy[idx].key = val;
                            return copy;
                          });
                        }}
                        className="h-9 text-xs"
                      />
                      <Input
                        placeholder="Header Value"
                        value={header.value}
                        onChange={(e) => {
                          const val = e.target.value;
                          setCustomHeaders((prev) => {
                            const copy = [...prev];
                            copy[idx].value = val;
                            return copy;
                          });
                        }}
                        className="h-9 text-xs"
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-9 w-9 text-destructive"
                        onClick={() => setCustomHeaders((prev) => prev.filter((_, i) => i !== idx))}
                      >
                        <RotateCcw className="h-3.5 w-3.5 rotate-45" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Scenario Contents */}
          {activeTab === 'overview' && (
            <Card>
              <CardHeader>
                <CardTitle>Approved Scenarios Index</CardTitle>
                <CardDescription>Select a scenario to verify application behaviors interactively.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div
                    onClick={() => setActiveTab('otp')}
                    className="group border border-muted hover:border-primary/50 bg-muted/20 hover:bg-primary/5 p-4 rounded-xl cursor-pointer transition-all space-y-2"
                  >
                    <div className="flex items-center gap-2">
                      <Send className="h-4 w-4 text-primary" />
                      <h4 className="font-semibold text-sm group-hover:text-primary">OTP Delivery & Verification</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Sends a real verification OTP to an email/phone destination and validates it against the active database instance.
                    </p>
                  </div>

                  <div
                    onClick={() => setActiveTab('permissions')}
                    className="group border border-muted hover:border-primary/50 bg-muted/20 hover:bg-primary/5 p-4 rounded-xl cursor-pointer transition-all space-y-2"
                  >
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-primary" />
                      <h4 className="font-semibold text-sm group-hover:text-primary">Permission Checker Tool</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Verify whether a specific user holds specific scoped permissions on a tenant using backend checker API.
                    </p>
                  </div>

                  <div
                    onClick={() => setActiveTab('session')}
                    className="group border border-muted hover:border-primary/50 bg-muted/20 hover:bg-primary/5 p-4 rounded-xl cursor-pointer transition-all space-y-2"
                  >
                    <div className="flex items-center gap-2">
                      <UserCheck className="h-4 w-4 text-primary" />
                      <h4 className="font-semibold text-sm group-hover:text-primary">Admin Session Details</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Tests user profile data loading (`/users/me`) using current browser authentication cookies and state.
                    </p>
                  </div>

                  <div
                    onClick={() => setActiveTab('token')}
                    className="group border border-muted hover:border-primary/50 bg-muted/20 hover:bg-primary/5 p-4 rounded-xl cursor-pointer transition-all space-y-2"
                  >
                    <div className="flex items-center gap-2">
                      <Activity className="h-4 w-4 text-primary" />
                      <h4 className="font-semibold text-sm group-hover:text-primary">Token Introspection</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Validates user/service access tokens against backend token introspection parser safely.
                    </p>
                  </div>
                </div>

                <div className="rounded-lg bg-yellow-500/10 border border-yellow-500/20 p-4 text-xs text-yellow-800 dark:text-yellow-300 flex items-start gap-2.5">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-yellow-500 mt-0.5" />
                  <div>
                    <h5 className="font-bold">Security Notice: Active API Execution</h5>
                    <p className="opacity-90 mt-0.5">
                      Executing scenarios from this lab initiates real requests to the MiniSource core API server. Operations such as OTP sending are fully dispatched to real providers and are subject to active rate limits and anti-abuse systems.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {activeTab === 'otp' && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Send className="h-5 w-5 text-primary" /> Real-time OTP Delivery Scenario
                </CardTitle>
                <CardDescription>
                  Walk through triggering, dispatching, and verifying OTP codes using delivery providers.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Visual Stepper */}
                <div className="grid grid-cols-3 gap-2 border-b border-muted pb-4">
                  {otpSteps.map((step) => (
                    <div key={step.number} className="flex flex-col gap-1">
                      <div className="flex items-center gap-1.5">
                        <span className={`h-5 w-5 rounded-full flex items-center justify-center text-xs font-bold ${
                          step.state === 'success' ? 'bg-green-500 text-white' :
                          step.state === 'failed' ? 'bg-red-500 text-white' :
                          step.state === 'running' ? 'bg-primary text-white animate-pulse' :
                          'bg-muted text-muted-foreground'
                        }`}>
                          {step.number}
                        </span>
                        <span className="text-xs font-semibold">{step.title}</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground capitalize">Status: {step.state}</span>
                    </div>
                  ))}
                </div>

                {/* Step 1 Form */}
                <div className="space-y-4 p-4 rounded-xl border border-muted bg-muted/10">
                  <h4 className="font-bold text-sm flex items-center gap-2">
                    <span className="h-4 w-4 text-xs bg-muted border border-muted-foreground/30 rounded-full flex items-center justify-center">1</span>
                    Request Delivery Details
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="space-y-1.5">
                      <Label>Destination Type</Label>
                      <div className="flex gap-2">
                        <Button
                          variant={otpType === 'phone' ? 'default' : 'outline'}
                          size="sm"
                          onClick={() => setOtpType('phone')}
                        >
                          Phone No
                        </Button>
                        <Button
                          variant={otpType === 'email' ? 'default' : 'outline'}
                          size="sm"
                          onClick={() => setOtpType('email')}
                        >
                          Email Address
                        </Button>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <Label>Purpose</Label>
                      <select
                        value={otpPurpose}
                        onChange={(e) => setOtpPurpose(e.target.value)}
                        className="w-full h-9 px-3 rounded-lg border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                      >
                        <option value="login">Login / Sign In</option>
                        <option value="verify-email">Email Verification</option>
                        <option value="reset-password">Password Reset</option>
                      </select>
                    </div>

                    <div className="space-y-1.5">
                      <Label>Destination Address</Label>
                      <Input
                        value={otpDestination}
                        onChange={(e) => setOtpDestination(e.target.value)}
                        placeholder={otpType === 'phone' ? '+989123456789' : 'admin@example.com'}
                      />
                    </div>
                  </div>
                  <Button onClick={handleOTPRequest} disabled={executing} className="w-full">
                    {executing ? 'Requesting OTP...' : 'Send Real Verification Code'}
                  </Button>
                </div>

                {/* Step 2 Form */}
                <div className="space-y-4 p-4 rounded-xl border border-muted bg-muted/10">
                  <h4 className="font-bold text-sm flex items-center gap-2">
                    <span className="h-4 w-4 text-xs bg-muted border border-muted-foreground/30 rounded-full flex items-center justify-center">2</span>
                    Verify Code
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
                    <div className="space-y-1.5">
                      <Label>OTP Code (Delivered to Target)</Label>
                      <Input
                        value={otpCode}
                        onChange={(e) => setOtpCode(e.target.value)}
                        placeholder="Enter the 6-digit code"
                      />
                    </div>
                    <Button onClick={handleOTPVerify} disabled={executing || otpSteps[0].state !== 'success'} className="w-full">
                      Verify and Login
                    </Button>
                  </div>
                </div>

                {/* Step 3 Form */}
                <div className="space-y-4 p-4 rounded-xl border border-muted bg-muted/10">
                  <h4 className="font-bold text-sm flex items-center gap-2">
                    <span className="h-4 w-4 text-xs bg-muted border border-muted-foreground/30 rounded-full flex items-center justify-center">3</span>
                    Authenticated Follow-Up
                  </h4>
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="text-xs">
                      <p className="font-semibold">Verify resulting token session:</p>
                      <p className="text-muted-foreground truncate max-w-sm">
                        {sessionTokenChained ? `Session Token: ${sessionTokenChained.substring(0, 15)}...` : 'No token received yet (Complete Step 2)'}
                      </p>
                    </div>
                    <Button
                      onClick={handleOTPFollowUp}
                      disabled={executing || !sessionTokenChained}
                      variant="secondary"
                    >
                      Fetch User Details
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {activeTab === 'session' && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <UserCheck className="h-5 w-5 text-primary" /> Current Session Verification
                </CardTitle>
                <CardDescription>
                  Tests loading user data based on the current admin session.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm">
                  This validates that the user's browser credentials can securely retrieve profile metadata `/users/me`.
                </p>
                <Button onClick={handleFetchSession} disabled={executing} className="w-full">
                  Fetch Profile Details
                </Button>
              </CardContent>
            </Card>
          )}

          {activeTab === 'token' && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-primary" /> Access Token Introspection
                </CardTitle>
                <CardDescription>
                  Validate and inspect JWT access tokens.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label>Introspection API Method</Label>
                    <select
                      value={introspectionApi}
                      onChange={(e) => setIntrospectionApi(e.target.value as any)}
                      className="w-full h-9 px-3 rounded-lg border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                    >
                      <option value="auth">Public Endpoint (/auth/introspect)</option>
                      <option value="admin">Admin Tools Endpoint (/admin/tools/introspect-token)</option>
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Token String</Label>
                    <Input
                      value={tokenToValidate}
                      onChange={(e) => setTokenToValidate(e.target.value)}
                      placeholder="Paste access_token here..."
                    />
                  </div>
                </div>
                <Button onClick={handleValidateToken} disabled={executing} className="w-full">
                  Introspect Token
                </Button>
              </CardContent>
            </Card>
          )}

          {activeTab === 'health' && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Heart className="h-5 w-5 text-primary" /> Health Check Diagnostics
                </CardTitle>
                <CardDescription>
                  Query health check, readiness state, or JWKS status parameters.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Health Diagnostics Target</Label>
                  <select
                    value={healthTarget}
                    onChange={(e) => setHealthTarget(e.target.value as any)}
                    className="w-full h-10 px-3 rounded-lg border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  >
                    <option value="system">Core System Health Check (/health)</option>
                    <option value="ready">System Readiness Check (/ready)</option>
                    <option value="tools">Admin Tools API Status Check (/v1/admin/tools/health)</option>
                    <option value="jwks">JWKS Status & Public Keys Verification (/v1/admin/tools/jwks-status)</option>
                  </select>
                </div>
                <Button onClick={handleFetchHealth} disabled={executing} className="w-full">
                  Run Diagnostics Check
                </Button>
              </CardContent>
            </Card>
          )}

          {activeTab === 'permissions' && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" /> Admin Permission Diagnostics Tool
                </CardTitle>
                <CardDescription>
                  Interactively check if a user holds specific permissions on a given tenant.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-1.5">
                    <Label>User ID *</Label>
                    <Input
                      value={permissionUserId}
                      onChange={(e) => setPermissionUserId(e.target.value)}
                      placeholder="User UUID"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>Permission Key *</Label>
                    <Input
                      value={permissionKey}
                      onChange={(e) => setPermissionKey(e.target.value)}
                      placeholder="e.g. users:write"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>Tenant ID (Optional)</Label>
                    <Input
                      value={permissionTenantId}
                      onChange={(e) => setPermissionTenantId(e.target.value)}
                      placeholder="Tenant UUID"
                    />
                  </div>
                </div>
                <Button onClick={handleCheckPermission} disabled={executing} className="w-full">
                  Execute Permission Validation Check
                </Button>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Right Side: Diagnostics Inspector and History */}
        <div className="lg:col-span-4 space-y-6">
          {/* History Card */}
          <Card className="border border-muted bg-card/30">
            <CardHeader className="py-4">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <History className="h-4 w-4 text-muted-foreground" /> Local Execution History
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-48 overflow-y-auto divide-y divide-muted border-t border-muted">
                {history.length === 0 ? (
                  <div className="py-6 text-center text-xs text-muted-foreground">No operations executed in this session.</div>
                ) : (
                  history.map((item) => (
                    <div
                      key={item.id}
                      onClick={() => setSelectedHistoryItem(item)}
                      className={`p-3 text-xs cursor-pointer hover:bg-muted/30 transition-colors flex justify-between items-center ${
                        selectedHistoryItem?.id === item.id ? 'bg-primary/5 border-l-2 border-primary' : ''
                      }`}
                    >
                      <div className="space-y-0.5 pr-2 truncate">
                        <p className="font-semibold truncate">{item.operationId}</p>
                        <p className="text-[10px] text-muted-foreground">{item.timestamp}</p>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="font-mono text-[10px] text-muted-foreground">{item.duration}ms</span>
                        <Badge
                          variant="outline"
                          className={item.success ? 'bg-green-500/10 text-green-600 border-green-500/20' : 'bg-red-500/10 text-red-600 border-red-500/20'}
                        >
                          {item.statusCode}
                        </Badge>
                      </div>
                    </div>
                  ))
                )}
              </div>
              {history.length > 0 && (
                <div className="p-2 border-t border-muted text-right">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-[10px] h-7 px-2"
                    onClick={() => {
                      setHistory([]);
                      setSelectedHistoryItem(null);
                      setDiagnosticResult(null);
                    }}
                  >
                    Clear History
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Diagnostic Inspector */}
          {(selectedHistoryItem || diagnosticResult) && (
            <Card className="border border-muted bg-card/60 backdrop-blur-md">
              <CardHeader className="py-4 border-b border-muted">
                <CardTitle className="text-sm font-semibold flex items-center justify-between">
                  <span>Diagnostics Inspector</span>
                  <div className="flex gap-1.5">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => handleCopy(selectedHistoryItem || diagnosticResult, 'Diagnostic Data')}
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 space-y-4 max-h-[550px] overflow-y-auto">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2 rounded-lg bg-muted/20">
                    <p className="text-muted-foreground font-semibold">Status Code</p>
                    <p className="font-mono text-base font-bold mt-0.5 flex items-center gap-1.5">
                      {(selectedHistoryItem || diagnosticResult).success ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      {(selectedHistoryItem || diagnosticResult).statusCode}
                    </p>
                  </div>
                  <div className="p-2 rounded-lg bg-muted/20">
                    <p className="text-muted-foreground font-semibold">Duration</p>
                    <p className="font-mono text-base font-bold mt-0.5 flex items-center gap-1">
                      <Clock className="h-4 w-4 text-muted-foreground" /> {(selectedHistoryItem || diagnosticResult).duration}ms
                    </p>
                  </div>
                </div>

                <div className="p-2.5 rounded-lg bg-muted/30 border border-muted text-[11px] font-mono space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground font-semibold">Request ID:</span>
                    <span className="truncate max-w-[150px]">{(selectedHistoryItem || diagnosticResult).requestId}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground font-semibold">Correlation ID:</span>
                    <span className="truncate max-w-[150px]">{(selectedHistoryItem || diagnosticResult).correlationId}</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <p className="text-xs font-bold uppercase text-muted-foreground">Request Details</p>
                  <div className="p-2 rounded-lg bg-black/5 dark:bg-black/20 text-xs font-mono">
                    <div className="flex items-center gap-1.5 mb-1.5">
                      <Badge variant="default" className="text-[10px] py-0.5">
                        {(selectedHistoryItem || diagnosticResult).request?.method}
                      </Badge>
                      <span className="text-muted-foreground truncate font-semibold">
                        {(selectedHistoryItem || diagnosticResult).request?.url}
                      </span>
                    </div>
                    <p className="text-[10px] text-muted-foreground font-semibold mb-1">Body:</p>
                    <pre className="p-2 rounded bg-muted/30 max-h-24 overflow-y-auto text-[10px] whitespace-pre-wrap">
                      {JSON.stringify((selectedHistoryItem || diagnosticResult).request?.body || {}, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <p className="text-xs font-bold uppercase text-muted-foreground">Sanitized Response</p>
                  <div className="p-2 rounded-lg bg-black/5 dark:bg-black/20 text-xs font-mono">
                    <p className="text-[10px] text-muted-foreground font-semibold mb-1">Headers:</p>
                    <pre className="p-2 rounded bg-muted/30 max-h-20 overflow-y-auto text-[10px] whitespace-pre-wrap">
                      {JSON.stringify((selectedHistoryItem || diagnosticResult).response?.headers || {}, null, 2)}
                    </pre>
                    <p className="text-[10px] text-muted-foreground font-semibold my-1">Body:</p>
                    <pre className="p-2 rounded bg-muted/30 max-h-40 overflow-y-auto text-[10px] whitespace-pre-wrap">
                      {JSON.stringify((selectedHistoryItem || diagnosticResult).response?.body || {}, null, 2)}
                    </pre>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
