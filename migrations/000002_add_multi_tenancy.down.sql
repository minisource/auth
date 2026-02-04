-- Remove tenant_id columns from auth database tables

-- Remove indexes first
DROP INDEX IF EXISTS idx_user_roles_tenant;
DROP INDEX IF EXISTS idx_role_permissions_tenant;
DROP INDEX IF EXISTS idx_permissions_tenant;
DROP INDEX IF EXISTS idx_roles_name_tenant;
DROP INDEX IF EXISTS idx_roles_tenant;
DROP INDEX IF EXISTS idx_sessions_user_tenant;
DROP INDEX IF EXISTS idx_sessions_tenant;
DROP INDEX IF EXISTS idx_users_phone_tenant;
DROP INDEX IF EXISTS idx_users_email_tenant;
DROP INDEX IF EXISTS idx_users_tenant;

-- Remove tenant_id columns
ALTER TABLE role_permissions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE user_roles DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE permissions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE roles DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;

-- Drop tenants table
DROP TABLE IF EXISTS tenants;
