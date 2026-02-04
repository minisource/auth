-- Rollback database optimizations
-- Migration: 000004_optimize_database

-- Drop audit logs indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_user_activity;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_entity;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_time_action;

-- Drop settings indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_settings_tenant_key;

-- Drop OAuth indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_oauth_user;
DROP INDEX CONCURRENTLY IF EXISTS idx_oauth_provider_user;

-- Drop OTP indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_otps_expired;
DROP INDEX CONCURRENTLY IF EXISTS idx_otps_tenant_identifier_valid;

-- Drop role and permission indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_role_permissions_composite;
DROP INDEX CONCURRENTLY IF EXISTS idx_role_permissions_permission;
DROP INDEX CONCURRENTLY IF EXISTS idx_role_permissions_role;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_roles_composite;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_roles_role;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_roles_user;
DROP INDEX CONCURRENTLY IF EXISTS idx_permissions_tenant_resource;
DROP INDEX CONCURRENTLY IF EXISTS idx_roles_tenant_name;

-- Drop login logs indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_login_logs_ip_recent;
DROP INDEX CONCURRENTLY IF EXISTS idx_login_logs_failed;
DROP INDEX CONCURRENTLY IF EXISTS idx_login_logs_tenant_user_time;

-- Drop refresh tokens indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_refresh_tokens_token;
DROP INDEX CONCURRENTLY IF EXISTS idx_refresh_tokens_tenant_user_valid;

-- Drop sessions indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_sessions_token_hash;
DROP INDEX CONCURRENTLY IF EXISTS idx_sessions_expired;
DROP INDEX CONCURRENTLY IF EXISTS idx_sessions_tenant_user_valid;

-- Drop users indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_users_name_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_email_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_reset_token;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_verification_token;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_tenant_email_active;

-- Reset autovacuum settings to defaults
ALTER TABLE sessions RESET (autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor);
ALTER TABLE login_logs RESET (autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor);
ALTER TABLE audit_logs RESET (autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor);

-- Note: Extensions are not dropped as they may be used by other databases
-- DROP EXTENSION IF EXISTS pg_trgm;
-- DROP EXTENSION IF EXISTS pg_stat_statements;
