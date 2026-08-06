-- Database Optimization - Add advanced indexes and performance improvements
-- Migration: 000004_optimize_database

-- Enable pg_stat_statements extension for query monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Enable pg_trgm for faster LIKE/ILIKE queries
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ==========================================
-- USERS TABLE OPTIMIZATIONS
-- ==========================================

-- Composite index for common login query (tenant + email)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_email_active 
ON users(tenant_id, email) 
WHERE deleted_at IS NULL AND is_active = true;

-- GIN index for email verification lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_verification_token 
ON users(email_verification_token) 
WHERE email_verified = false AND deleted_at IS NULL;

-- Index for password reset operations
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_reset_token 
ON users(password_reset_token, password_reset_expires) 
WHERE password_reset_token IS NOT NULL AND deleted_at IS NULL;

-- Trigram index for user search (LIKE queries)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_trgm 
ON users USING gin(email gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_name_trgm 
ON users USING gin(name gin_trgm_ops);

-- ==========================================
-- SESSIONS TABLE OPTIMIZATIONS
-- ==========================================

-- Composite index for session validation (tenant + user + expiry)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_tenant_user_valid 
ON sessions(tenant_id, user_id, expires_at) 
WHERE expires_at > CURRENT_TIMESTAMP;

-- Index for session cleanup (expired sessions)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_expired 
ON sessions(expires_at) 
WHERE expires_at <= CURRENT_TIMESTAMP;

-- B-tree index for token lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_token_hash 
ON sessions(token) 
WHERE expires_at > CURRENT_TIMESTAMP;

-- ==========================================
-- REFRESH TOKENS TABLE OPTIMIZATIONS
-- ==========================================

-- Index for refresh token validation
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_tenant_user_valid 
ON refresh_tokens(tenant_id, user_id, expires_at, is_revoked) 
WHERE expires_at > CURRENT_TIMESTAMP AND is_revoked = false;

-- Index for token lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_token 
ON refresh_tokens(token) 
WHERE expires_at > CURRENT_TIMESTAMP AND is_revoked = false;

-- ==========================================
-- LOGIN LOGS TABLE OPTIMIZATIONS
-- ==========================================

-- Composite index for user login history
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_logs_tenant_user_time 
ON login_logs(tenant_id, user_id, login_time DESC, was_successful);

-- Index for security monitoring (failed logins)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_logs_failed 
ON login_logs(tenant_id, ip_address, login_time DESC) 
WHERE was_successful = false;

-- Index for IP-based rate limiting
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_logs_ip_recent 
ON login_logs(ip_address, login_time DESC) 
WHERE login_time > CURRENT_TIMESTAMP - INTERVAL '1 hour';

-- ==========================================
-- ROLES & PERMISSIONS OPTIMIZATIONS
-- ==========================================

-- Index for role lookups by name
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_tenant_name 
ON roles(tenant_id, name) 
WHERE deleted_at IS NULL;

-- Index for permission lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_permissions_tenant_resource 
ON permissions(tenant_id, resource, action);

-- Index for user_roles junction table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_roles_user 
ON user_roles(user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_roles_role 
ON user_roles(role_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_roles_composite 
ON user_roles(user_id, role_id);

-- Index for role_permissions junction table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_role_permissions_role 
ON role_permissions(role_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_role_permissions_permission 
ON role_permissions(permission_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_role_permissions_composite 
ON role_permissions(role_id, permission_id);

-- ==========================================
-- OTP TABLE OPTIMIZATIONS
-- ==========================================

-- Index for OTP validation
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_otps_tenant_identifier_valid 
ON otps(tenant_id, identifier, otp_type, expires_at) 
WHERE is_used = false AND expires_at > CURRENT_TIMESTAMP;

-- Index for cleanup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_otps_expired 
ON otps(expires_at) 
WHERE expires_at <= CURRENT_TIMESTAMP OR is_used = true;

-- ==========================================
-- OAUTH ACCOUNTS OPTIMIZATIONS
-- ==========================================

-- Unique index for OAuth provider + provider_user_id
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_oauth_provider_user 
ON oauth_accounts(provider, provider_user_id);

-- Index for user OAuth accounts lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_oauth_user 
ON oauth_accounts(user_id);

-- ==========================================
-- SETTINGS TABLE OPTIMIZATIONS
-- ==========================================

-- Unique index for settings key per tenant
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_settings_tenant_key 
ON settings(tenant_id, key);

-- ==========================================
-- AUDIT LOGS OPTIMIZATIONS
-- ==========================================

-- Partitioned index for time-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_time_action 
ON audit_logs(created_at DESC, action, tenant_id);

-- Index for entity tracking
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_entity 
ON audit_logs(tenant_id, entity_type, entity_id, created_at DESC);

-- Index for user activity tracking
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_activity 
ON audit_logs(tenant_id, user_id, created_at DESC) 
WHERE user_id IS NOT NULL;

-- ==========================================
-- STATISTICS AND QUERY PLANNING
-- ==========================================

-- Update statistics for better query plans
ANALYZE users;
ANALYZE sessions;
ANALYZE refresh_tokens;
ANALYZE login_logs;
ANALYZE roles;
ANALYZE permissions;
ANALYZE user_roles;
ANALYZE role_permissions;
ANALYZE otps;
ANALYZE oauth_accounts;
ANALYZE settings;
ANALYZE audit_logs;

-- ==========================================
-- VACUUM AND MAINTENANCE
-- ==========================================

-- Configure autovacuum settings for high-activity tables
ALTER TABLE sessions SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02
);

ALTER TABLE login_logs SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02
);

ALTER TABLE audit_logs SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02
);

-- ==========================================
-- COMMENTS FOR DOCUMENTATION
-- ==========================================

COMMENT ON INDEX idx_users_tenant_email_active IS 'Optimizes login queries with tenant isolation';
COMMENT ON INDEX idx_sessions_tenant_user_valid IS 'Optimizes session validation queries';
COMMENT ON INDEX idx_refresh_tokens_token IS 'Optimizes refresh token lookups';
COMMENT ON INDEX idx_login_logs_failed IS 'Supports security monitoring and rate limiting';
COMMENT ON INDEX idx_audit_logs_time_action IS 'Optimizes audit log queries by time and action';
