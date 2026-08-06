# Minisource Auth Frontend

A comprehensive admin dashboard for the Minisource Authentication Service. Built with Next.js 15, shadcn/ui, TypeScript, and best practices.

## Features

### Authentication
- **Email/Password Login** - Secure login with JWT tokens
- **Phone OTP Login** - Login via SMS OTP with auto-registration
- **Google OAuth2** - Single sign-on with Google
- **Registration** - New user registration with email verification
- **Password Management** - Forgot/reset password with OTP

### User Management (Admin)
- **User CRUD** - Create, read, update, delete users
- **User Search** - Search users by name, email, or phone
- **Status Management** - Activate/deactivate users
- **Account Unlock** - Unlock locked accounts
- **Email/Phone Verification** - Mark verification status

### Role-Based Access Control (RBAC)
- **Role Management** - Create, edit, delete roles
- **Permission Management** - Define granular permissions
- **Resource/Action Permissions** - Fine-grained access control
- **Permission Assignment** - Assign permissions to roles

### Profile & Security
- **Profile Settings** - Update personal information
- **Password Change** - Change current password
- **Session Management** - View and revoke active sessions
- **Linked Accounts** - Manage OAuth-linked accounts

### Service-to-Service Auth
- **Service Clients** - Manage microservice authentication
- **OAuth2 Client Credentials** - Service token management
- **Scope Management** - Define service permissions

## Tech Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript (strict)
- **UI**: shadcn/ui, Tailwind CSS, Radix UI
- **State**: Zustand (persisted), TanStack Query
- **Forms**: React Hook Form + Zod validation
- **Icons**: Lucide React
- **Notifications**: Sonner (toasts)
- **HTTP Client**: Axios with interceptors

## Quick Start

### Prerequisites

- Node.js 20.x or higher
- npm 10.x or higher

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/minisource/minisource.git
   cd front
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your API URL
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   Navigate to [http://localhost:3003](http://localhost:3003)

## Project Structure

```
front/
├── public/                     # Static assets
├── src/
│   ├── api/                    # API layer (separated from UI)
│   │   ├── client.ts           # Axios client with interceptors
│   │   ├── base.ts             # Base API class
│   │   ├── index.ts            # API exports
│   │   └── services/
│   │       ├── auth.ts         # Authentication API
│   │       ├── user.ts         # User profile API
│   │       └── admin.ts        # Admin API (users, roles, permissions)
│   ├── app/
│   │   ├── (auth)/             # Auth routes (login, register, forgot-password)
│   │   ├── (main)/             # Main app routes
│   │   │   ├── admin/          # Admin pages
│   │   │   │   ├── users/      # User management
│   │   │   │   ├── roles/      # Role management
│   │   │   │   ├── permissions/ # Permission management
│   │   │   │   └── service-clients/ # Service client management
│   │   │   ├── profile/        # Profile & sessions
│   │   │   └── dashboard/      # Admin dashboard
│   │   ├── layout.tsx          # Root layout
│   │   └── page.tsx            # Landing page
│   ├── components/
│   │   ├── layout/             # Layout components (header, sidebar, footer)
│   │   ├── providers/          # Context providers
│   │   └── ui/                 # shadcn/ui components
│   ├── config/                 # App configuration & constants
│   ├── hooks/                  # React Query hooks
│   ├── lib/                    # Utility functions
│   ├── stores/                 # Zustand stores
│   ├── styles/                 # Global styles (Tailwind)
│   └── types/                  # TypeScript type definitions
├── Dockerfile                  # Production Dockerfile
├── Dockerfile.dev              # Development Dockerfile
├── docker-compose.yml          # Production Docker Compose
├── docker-compose.dev.yml      # Development Docker Compose
├── docker-compose.prod.yml     # Production Docker Compose (image)
└── .env.example                # Environment variables template
```

## Available Scripts

```bash
# Development
npm run dev           # Start development server
npm run dev:turbo     # Start with Turbopack

# Build
npm run build         # Create production build
npm run start         # Start production server

# Code Quality
npm run lint          # Run ESLint
npm run format        # Format with Prettier
npm run type-check    # Run TypeScript check

# Testing
npm run test          # Run tests
npm run test:coverage # Run tests with coverage

# Docker
npm run docker:build  # Build Docker image
npm run docker:dev    # Start development container
npm run docker:prod   # Start production container
```

## API Layer

The API layer is separated from the UI following clean architecture principles:

```typescript
// src/api/services/auth.ts - Auth service
authApi.login({ email, password })
authApi.register({ email, password, firstName, lastName })
authApi.sendOTP({ phone, type: 'login' })
authApi.verifyOTP({ target, code, type: 'login' })

// src/api/services/admin.ts - Admin service
adminApi.listUsers({ page, pageSize, search })
adminApi.listRoles()
adminApi.listPermissions(resource)
adminApi.createServiceClient({ name, scopes })
```

## API Endpoints

This frontend connects to the [Minisource Auth Service](https://github.com/minisource/auth) backend API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login with email/password |
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/otp/send` | Send OTP |
| POST | `/api/v1/auth/otp/verify` | Verify OTP and login |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout |
| GET | `/api/v1/auth/google` | Google OAuth URL |
| POST | `/api/v1/auth/forgot-password` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Reset password with OTP |
| GET | `/api/v1/users/me` | Get current user profile |
| PUT | `/api/v1/users/me` | Update profile |
| PUT | `/api/v1/users/me/password` | Change password |
| GET | `/api/v1/users/me/sessions` | Get active sessions |
| GET | `/api/v1/admin/users` | List users (admin) |
| GET | `/api/v1/admin/users/:id` | Get user (admin) |
| PUT | `/api/v1/admin/users/:id` | Update user (admin) |
| DELETE | `/api/v1/admin/users/:id` | Delete user (admin) |
| GET | `/api/v1/admin/roles` | List roles |
| POST | `/api/v1/admin/roles` | Create role |
| GET | `/api/v1/admin/permissions` | List permissions |
| POST | `/api/v1/admin/permissions` | Create permission |
| POST | `/api/v1/admin/service-clients` | Create service client |

## Docker

```bash
# Development
docker compose -f docker-compose.dev.yml up

# Production (build from source)
docker compose up -d

# Production (pre-built image)
export TAG=latest
docker compose -f docker-compose.prod.yml up -d
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXT_PUBLIC_APP_NAME` | Application name | Minisource Auth |
| `NEXT_PUBLIC_APP_URL` | Application URL | http://localhost:3003 |
| `NEXT_PUBLIC_API_URL` | Auth API URL | http://localhost:9001/api/v1 |
| `NEXT_PUBLIC_API_TIMEOUT` | API timeout (ms) | 30000 |

## License

MIT License - see LICENSE file for details.
