# Auth Microservice

A comprehensive authentication and authorization microservice built with Go and the Fiber framework. It provides user management, JWT authentication, OAuth2 support, OTP verification, and service-to-service authentication.

## Features

- **User Authentication**
  - Email/password login
  - Phone OTP login
  - Google OAuth2 login
  - JWT token management (access + refresh tokens)
  - Password reset with OTP

- **User Management**
  - User registration
  - Profile management
  - Email/phone verification
  - Session management

- **Authorization**
  - Role-based access control (RBAC)
  - Permission management
  - Multi-tenant support

- **Service-to-Service Auth**
  - OAuth2 client credentials flow
  - Service token validation
  - Scope-based authorization

- **Security Features**
  - Rate limiting
  - Account lockout after failed attempts
  - Login attempt logging
  - Secure password hashing (bcrypt)

## Tech Stack

- **Language**: Go 1.24
- **Framework**: Fiber v2
- **Database**: PostgreSQL
- **Cache**: Redis
- **Auth**: JWT, OAuth2
- **gRPC**: Service-to-service communication

## Quick Start

### Prerequisites

- Go 1.24+
- PostgreSQL 15+
- Redis 7+

### Installation

1. Clone the repository:
```bash
cd auth
```

2. Copy the environment file:
```bash
cp .env.example .env
```

3. Configure the `.env` file with your settings.

4. Run the service:
```bash
make run
```

Or with Docker:
```bash
docker-compose up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP server port | `9001` |
| `SERVER_MODE` | Server mode (development/production) | `development` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | - |
| `DB_NAME` | Database name | `auth_db` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_ACCESS_EXPIRY` | Access token expiry | `15m` |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | `168h` |

See `.env.example` for all configuration options.

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login with email/password |
| POST | `/api/v1/auth/login/otp/send` | Send OTP for login |
| POST | `/api/v1/auth/login/otp/verify` | Verify OTP and login |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout user |
| GET | `/api/v1/auth/google/login` | Initiate Google OAuth |
| GET | `/api/v1/auth/google/callback` | Google OAuth callback |

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me` | Get current user profile |
| PUT | `/api/v1/users/me` | Update current user profile |
| PUT | `/api/v1/users/me/password` | Change password |
| POST | `/api/v1/users/password/forgot` | Request password reset |
| POST | `/api/v1/users/password/reset` | Reset password with OTP |

### Service Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/service/token` | Get service access token |
| POST | `/api/v1/service/validate` | Validate service token |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/users` | List all users |
| GET | `/api/v1/admin/users/:id` | Get user by ID |
| PUT | `/api/v1/admin/users/:id` | Update user |
| DELETE | `/api/v1/admin/users/:id` | Delete user |
| GET | `/api/v1/admin/roles` | List all roles |
| POST | `/api/v1/admin/roles` | Create role |
| PUT | `/api/v1/admin/roles/:id` | Update role |
| DELETE | `/api/v1/admin/roles/:id` | Delete role |

## gRPC API

The auth service also exposes a gRPC API on port 9004 for service-to-service communication:

- `ValidateToken(token)` - Validate JWT token
- `ValidateServiceToken(token)` - Validate service token
- `GetUserInfo(userId)` - Get user information

## Project Structure

```
auth/
├── api/              # API route definitions
├── cmd/              # Application entry points
├── config/           # Configuration management
├── docs/             # Swagger documentation
├── internal/
│   ├── database/     # Database connection and migrations
│   ├── handlers/     # HTTP handlers
│   ├── models/       # Database models
│   ├── repository/   # Data access layer
│   ├── services/     # Business logic
│   └── grpc/         # gRPC server
├── migrations/       # Database migrations
├── pkg/              # Shared packages
└── scripts/          # Utility scripts
```

## Service OAuth Clients

The auth service manages OAuth clients for service-to-service authentication. Each microservice has credentials configured in `.env`:

| Service | Client ID | Scopes |
|---------|-----------|--------|
| auth-service | `auth-service` | `notifications:send,notifications:read` |
| gateway-service | `gateway-service` | `tokens:validate,users:read` |
| notifier-service | `notifier-service` | `tokens:validate` |
| log-service | `log-service` | `tokens:validate,logs:write,logs:read` |
| scheduler-service | `scheduler-service` | `tokens:validate,notifications:send,scheduler:admin` |
| storage-service | `storage-service` | `tokens:validate,storage:*` |
| comment-service | `comment-service` | `tokens:validate,notifications:send,comments:*` |
| feedback-service | `feedback-service` | `tokens:validate,notifications:send,storage:*,feedback:*` |
| ticket-service | `ticket-service` | `tokens:validate,notifications:send,storage:*,tickets:*` |
| payment-service | `payment-service` | `tokens:validate,notifications:send,payments:*,subscriptions:*` |

## Development

### Run Tests

```bash
make test
```

### Generate Swagger Docs

```bash
make swagger
```

### Build

```bash
make build
```

## Docker

Build and run with Docker:

```bash
# Build image
docker build -t auth-service .

# Run with docker-compose
docker-compose up -d
```

## Health Checks

| Endpoint | Description |
|----------|-------------|
| `/health` | Basic health check |
| `/ready` | Readiness probe |
| `/live` | Liveness probe |

## License

MIT License - see LICENSE file for details.
