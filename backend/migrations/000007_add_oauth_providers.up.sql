CREATE TABLE IF NOT EXISTS oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    client_id VARCHAR(500) NOT NULL,
    client_secret VARCHAR(2000) NOT NULL,
    redirect_url VARCHAR(500),
    scopes TEXT,
    auth_url VARCHAR(500),
    token_url VARCHAR(500),
    user_info_url VARCHAR(500),
    is_enabled BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    config JSONB DEFAULT '{}',
    total_logins BIGINT DEFAULT 0,
    successful_logins BIGINT DEFAULT 0,
    failed_logins BIGINT DEFAULT 0,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_oauth_providers_tenant ON oauth_providers(tenant_id);
CREATE UNIQUE INDEX idx_oauth_providers_type_tenant ON oauth_providers(type, tenant_id) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX idx_oauth_providers_type_global ON oauth_providers(type) WHERE tenant_id IS NULL;
