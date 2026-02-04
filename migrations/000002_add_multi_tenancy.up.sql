-- Add tenant_id columns to auth database tables

-- Add tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_active ON tenants(is_active) WHERE deleted_at IS NULL;

-- Add tenant_id to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email_tenant ON users(email, tenant_id) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_phone_tenant ON users(phone, tenant_id) WHERE phone IS NOT NULL;

-- Add tenant_id to sessions table
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_tenant ON sessions(user_id, tenant_id);

-- Add tenant_id to roles table
ALTER TABLE roles ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_name_tenant ON roles(name, tenant_id);

-- Add tenant_id to permissions table
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_permissions_tenant ON permissions(tenant_id);

-- Add tenant_id to user_roles table
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant ON user_roles(tenant_id);

-- Add tenant_id to role_permissions table
ALTER TABLE role_permissions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_tenant ON role_permissions(tenant_id);

-- Insert default tenant
INSERT INTO tenants (id, name, slug, is_active, settings)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 
    'Default Tenant', 
    'default', 
    true, 
    '{}'
) ON CONFLICT (slug) DO NOTHING;

-- Update existing records to use default tenant
UPDATE users SET tenant_id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' WHERE tenant_id IS NULL;
UPDATE sessions SET tenant_id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' WHERE tenant_id IS NULL;
UPDATE roles SET tenant_id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' WHERE tenant_id IS NULL;
UPDATE permissions SET tenant_id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' WHERE tenant_id IS NULL;
UPDATE user_roles SET tenant_id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' WHERE tenant_id IS NULL;
UPDATE role_permissions SET tenant_id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' WHERE tenant_id IS NULL;
