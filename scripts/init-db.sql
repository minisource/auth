-- Auth Service Database Initialization
-- This script runs once when the PostgreSQL container is first created

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant privileges (useful for production with separate db user)
-- Uncomment and modify for production use:
-- CREATE USER auth_user WITH PASSWORD 'your_password';
-- GRANT ALL PRIVILEGES ON DATABASE auth_db TO auth_user;
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auth_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auth_user;
