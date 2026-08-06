# Auth Microservice & Dashboard

A comprehensive authentication and authorization microservice built with Go (Fiber) and Next.js Admin Dashboard. Provides user management, JWT authentication, OAuth2 support, OTP verification, multi-tenant RBAC, and service-to-service authentication.

## Docker Images

Published to Docker Hub:
- **Backend**: `minisource/auth-backend:v1.0.1`
- **Frontend**: `minisource/auth-frontend:v1.0.1`

```bash
docker pull minisource/auth-backend:v1.0.1
docker pull minisource/auth-frontend:v1.0.1
```

## Features

- **User Authentication & Security**
  - Email/password login & Phone OTP login
  - Google OAuth2 & OpenID Connect
  - JWT Token lifecycle management (Access + Refresh tokens with rotation)
  - Password reset flows with secure OTP
  - Security headers, rate limiting, and account lockout

- **User & Multi-Tenant Management**
  - User registration & self-service profile management
  - Email & phone verification
  - Session tracking & active session invalidation
  - Multi-tenant tenant separation and RBAC (Role-Based Access Control)

- **Service-to-Service Authentication**
  - OAuth2 Client Credentials flow
  - Service client management & secret rotation
  - Scope-based authorization & token validation

- **Next.js Admin Dashboard (`front/`)**
  - Interactive management UI for users, sessions, tenants, and OAuth providers
  - Service Client API lab & client creation wizards
  - Login audit logs and security analytics

## Tech Stack

- **Backend**: Go 1.24, Fiber v2, PostgreSQL 15, Redis 7, gRPC
- **Frontend**: Next.js 14/15, React 19, TypeScript, TailwindCSS, `@minisource/ui`
- **CI/CD**: GitHub Actions, Docker Hub

## Repository Structure

```
auth/
├── backend/                  # Go HTTP API & gRPC Server
│   ├── cmd/
│   ├── internal/
│   └── Dockerfile
├── front/                    # Next.js Admin Panel
│   ├── src/
│   └── Dockerfile
├── docker-compose.prod.yml   # Production Compose setup
├── docker-compose.dev.yml    # Development Compose setup
└── .github/workflows/        # CI/CD Workflows
```

## Quick Start

### Running with Docker Compose

```bash
# Development stack (Postgres + Redis + Local build)
docker compose -f docker-compose.dev.yml up -d

# Production stack (Pulling from Docker Hub)
docker compose -f docker-compose.prod.yml up -d
```

### Local Development

#### Backend (Go)
```bash
cd backend
cp .env.example .env
go run ./cmd/server
```

#### Frontend (Next.js)
```bash
cd front
npm install --legacy-peer-deps
npm run dev
```

## Environment Variables

### Backend Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP server port | `9001` |
| `SERVER_MODE` | Server mode (`development`/`production`) | `development` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `auth_db` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `JWT_SECRET` | JWT signing secret | - |

### Frontend Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXT_PUBLIC_API_URL` | Auth Backend API URL | `http://localhost:9001` |

## CI/CD & Publishing

Automated by GitHub Actions (`.github/workflows/ci.yml`):
- **Backend CI**: Go tests & `go vet`
- **Frontend CI**: ESLint, TypeScript check (`tsc --noEmit`), and Vitest
- **Docker Push**: Automatically builds and publishes `minisource/auth-backend` & `minisource/auth-frontend` to Docker Hub upon tag pushes (`v*`).
