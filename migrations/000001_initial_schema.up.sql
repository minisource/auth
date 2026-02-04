-- Migration: initial_schema
-- Version: 1
-- Description: Create all initial tables for auth service

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================
-- TENANTS
-- ==========================================
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    description VARCHAR(1000),
    logo VARCHAR(500),
    domain VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active',
    is_default BOOLEAN DEFAULT FALSE,
    settings JSONB DEFAULT '{}',
    limits JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    plan VARCHAR(50) DEFAULT 'free',
    billing_cycle VARCHAR(20) DEFAULT 'monthly',
    plan_id UUID,
    trial_ends_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants(deleted_at);

-- ==========================================
-- USERS
-- ==========================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20) UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar VARCHAR(500),
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_super_admin BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45),
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

-- ==========================================
-- ROLES
-- ==========================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(200),
    description VARCHAR(500),
    is_system BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_role_name ON roles(tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_deleted_at ON roles(deleted_at);

-- ==========================================
-- PERMISSIONS
-- ==========================================
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(200),
    description VARCHAR(500),
    resource VARCHAR(100),
    action VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_deleted_at ON permissions(deleted_at);

-- ==========================================
-- USER ROLES (join table)
-- ==========================================
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

-- ==========================================
-- ROLE PERMISSIONS (join table)
-- ==========================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- ==========================================
-- SESSIONS
-- ==========================================
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token VARCHAR(500),
    refresh_token VARCHAR(500),
    user_agent VARCHAR(500),
    ip_address VARCHAR(45),
    device_type VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_access_token ON sessions(access_token);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ==========================================
-- REFRESH TOKENS
-- ==========================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) NOT NULL UNIQUE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_is_revoked ON refresh_tokens(is_revoked);

-- ==========================================
-- OTPs
-- ==========================================
CREATE TABLE IF NOT EXISTS otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    attempts INTEGER DEFAULT 0,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_otps_user_id ON otps(user_id);
CREATE INDEX IF NOT EXISTS idx_otps_type ON otps(type);
CREATE INDEX IF NOT EXISTS idx_otps_target ON otps(target);
CREATE INDEX IF NOT EXISTS idx_otps_is_used ON otps(is_used);
CREATE INDEX IF NOT EXISTS idx_otps_expires_at ON otps(expires_at);

-- ==========================================
-- OAUTH ACCOUNTS
-- ==========================================
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    name VARCHAR(200),
    avatar VARCHAR(500),
    access_token VARCHAR(2000),
    refresh_token VARCHAR(2000),
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_id ON oauth_accounts(provider_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_accounts_provider_provider_id ON oauth_accounts(provider, provider_id);

-- ==========================================
-- LOGIN LOGS
-- ==========================================
CREATE TABLE IF NOT EXISTS login_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    location VARCHAR(200),
    device VARCHAR(200),
    success BOOLEAN DEFAULT TRUE,
    error_msg VARCHAR(500),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_logs_user_id ON login_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_login_logs_session_id ON login_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_login_logs_action ON login_logs(action);
CREATE INDEX IF NOT EXISTS idx_login_logs_ip_address ON login_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_logs_success ON login_logs(success);
CREATE INDEX IF NOT EXISTS idx_login_logs_created_at ON login_logs(created_at);

-- ==========================================
-- SETTINGS
-- ==========================================
CREATE TABLE IF NOT EXISTS settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL UNIQUE,
    value TEXT,
    type VARCHAR(50) DEFAULT 'string',
    category VARCHAR(100),
    description VARCHAR(500),
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);
CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);
CREATE INDEX IF NOT EXISTS idx_settings_deleted_at ON settings(deleted_at);

-- ==========================================
-- SERVICE CLIENTS
-- ==========================================
CREATE TABLE IF NOT EXISTS service_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(255) NOT NULL,
    description VARCHAR(500),
    scopes VARCHAR(1000),
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_client_name ON service_clients(tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_service_clients_tenant_id ON service_clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_service_clients_client_id ON service_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_service_clients_deleted_at ON service_clients(deleted_at);

-- ==========================================
-- TENANT MEMBERS
-- ==========================================
CREATE TABLE IF NOT EXISTS tenant_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member',
    is_active BOOLEAN DEFAULT TRUE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_members_tenant_id ON tenant_members(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_members_user_id ON tenant_members(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_members_is_active ON tenant_members(is_active);

-- ==========================================
-- SEED DEFAULT DATA
-- ==========================================

-- Insert default system roles
INSERT INTO roles (id, name, display_name, description, is_system, is_active)
VALUES 
    (gen_random_uuid(), 'super_admin', 'Super Administrator', 'Full system access', TRUE, TRUE),
    (gen_random_uuid(), 'admin', 'Administrator', 'Administrative access', TRUE, TRUE),
    (gen_random_uuid(), 'user', 'User', 'Standard user access', TRUE, TRUE),
    (gen_random_uuid(), 'guest', 'Guest', 'Limited guest access', TRUE, TRUE),
    (gen_random_uuid(), 'service', 'Service', 'Service-to-service access', TRUE, TRUE)
ON CONFLICT DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (id, name, display_name, resource, action, is_active)
VALUES
    -- User permissions
    (gen_random_uuid(), 'users:read', 'View Users', 'users', 'read', TRUE),
    (gen_random_uuid(), 'users:create', 'Create Users', 'users', 'create', TRUE),
    (gen_random_uuid(), 'users:update', 'Update Users', 'users', 'update', TRUE),
    (gen_random_uuid(), 'users:delete', 'Delete Users', 'users', 'delete', TRUE),
    (gen_random_uuid(), 'users:manage', 'Manage Users', 'users', 'manage', TRUE),
    -- Role permissions
    (gen_random_uuid(), 'roles:read', 'View Roles', 'roles', 'read', TRUE),
    (gen_random_uuid(), 'roles:create', 'Create Roles', 'roles', 'create', TRUE),
    (gen_random_uuid(), 'roles:update', 'Update Roles', 'roles', 'update', TRUE),
    (gen_random_uuid(), 'roles:delete', 'Delete Roles', 'roles', 'delete', TRUE),
    (gen_random_uuid(), 'roles:manage', 'Manage Roles', 'roles', 'manage', TRUE),
    -- Permission permissions
    (gen_random_uuid(), 'permissions:read', 'View Permissions', 'permissions', 'read', TRUE),
    (gen_random_uuid(), 'permissions:create', 'Create Permissions', 'permissions', 'create', TRUE),
    (gen_random_uuid(), 'permissions:update', 'Update Permissions', 'permissions', 'update', TRUE),
    (gen_random_uuid(), 'permissions:delete', 'Delete Permissions', 'permissions', 'delete', TRUE),
    -- Notification permissions
    (gen_random_uuid(), 'notifications:send', 'Send Notifications', 'notifications', 'send', TRUE),
    (gen_random_uuid(), 'notifications:read', 'Read Notifications', 'notifications', 'read', TRUE),
    (gen_random_uuid(), 'notifications:manage', 'Manage Notifications', 'notifications', 'manage', TRUE),
    -- Settings permissions
    (gen_random_uuid(), 'settings:read', 'View Settings', 'settings', 'read', TRUE),
    (gen_random_uuid(), 'settings:update', 'Update Settings', 'settings', 'update', TRUE),
    -- Service client permissions
    (gen_random_uuid(), 'service_clients:read', 'View Service Clients', 'service_clients', 'read', TRUE),
    (gen_random_uuid(), 'service_clients:create', 'Create Service Clients', 'service_clients', 'create', TRUE),
    (gen_random_uuid(), 'service_clients:delete', 'Delete Service Clients', 'service_clients', 'delete', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles (using subqueries to get IDs)
-- Super Admin gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'super_admin'
ON CONFLICT DO NOTHING;

-- Admin gets user, role, notification, and settings permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'admin' 
AND p.name IN ('users:read', 'users:create', 'users:update', 'users:delete', 'users:manage',
               'roles:read', 'roles:create', 'roles:update', 
               'notifications:send', 'notifications:read', 'notifications:manage',
               'settings:read')
ON CONFLICT DO NOTHING;

-- Service role gets notification send permission (for microservices)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'service' 
AND p.name IN ('notifications:send', 'notifications:read')
ON CONFLICT DO NOTHING;

-- Insert default service client for notifier service
INSERT INTO service_clients (id, name, client_id, client_secret, description, scopes, is_active)
VALUES (
    gen_random_uuid(),
    'Auth Service',
    'auth-service-client',
    -- Note: In production, generate a secure secret and hash it
    '$2a$10$placeholder_hash_replace_in_production',
    'Auth service client for sending notifications',
    'notifications:send,notifications:read',
    TRUE
)
ON CONFLICT (client_id) DO NOTHING;

-- Insert default settings
INSERT INTO settings (id, key, value, type, category, description, is_public)
VALUES 
    (gen_random_uuid(), 'max_login_attempts', '5', 'int', 'security', 'Maximum failed login attempts before lockout', FALSE),
    (gen_random_uuid(), 'lock_duration_minutes', '30', 'int', 'security', 'Duration of account lockout in minutes', FALSE),
    (gen_random_uuid(), 'session_timeout_minutes', '60', 'int', 'security', 'Session timeout in minutes', FALSE),
    (gen_random_uuid(), 'otp_length', '6', 'int', 'auth', 'OTP code length', FALSE),
    (gen_random_uuid(), 'otp_expiry_minutes', '5', 'int', 'auth', 'OTP expiry time in minutes', FALSE),
    (gen_random_uuid(), 'allow_registration', 'true', 'bool', 'auth', 'Allow user self-registration', TRUE),
    (gen_random_uuid(), 'require_email_verification', 'true', 'bool', 'auth', 'Require email verification', FALSE),
    (gen_random_uuid(), 'enable_otp_login', 'true', 'bool', 'auth', 'Enable OTP-based login', TRUE)
ON CONFLICT (key) DO NOTHING;
