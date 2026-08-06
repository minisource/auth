# Integration Tests

## Overview
Integration tests for the Auth service that test complete API flows with a real database.

## Prerequisites
- PostgreSQL test database
- Go 1.21+
- Test environment variables configured

## Setup

### 1. Create Test Database
```bash
createdb auth_test
```

### 2. Run Migrations
```bash
cd auth
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_test?sslmode=disable"
make migrate-up
```

### 3. Set Environment Variables
```bash
export TEST_DB_HOST=localhost
export TEST_DB_PORT=5432
export TEST_DB_USER=postgres
export TEST_DB_PASSWORD=postgres
export TEST_DB_NAME=auth_test
```

## Running Tests

### Run All Integration Tests
```bash
go test -tags=integration ./tests/integration/...
```

### Run Specific Test
```bash
go test -tags=integration -run TestAuthFlow ./tests/integration/
```

### Run with Verbose Output
```bash
go test -tags=integration -v ./tests/integration/...
```

### Run with Coverage
```bash
go test -tags=integration -coverprofile=coverage.out ./tests/integration/...
go tool cover -html=coverage.out
```

## Test Structure

```
tests/
└── integration/
    ├── auth_test.go           # Authentication flow tests
    ├── user_test.go           # User management tests
    ├── role_test.go           # Role and permission tests
    └── README.md              # This file
```

## Test Scenarios

### Auth Flow Tests
- ✅ Successful login
- ✅ Invalid credentials
- ✅ User registration
- ✅ Password reset flow
- ✅ Email verification
- ✅ Refresh token

### User Management Tests
- Get user profile
- Update user profile
- Change password
- Get user sessions
- OAuth account linking

### Role & Permission Tests
- Create/update/delete roles
- Create/update/delete permissions
- Assign permissions to roles
- Assign roles to users
- Check user permissions

## Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Always clean up test data in defer
3. **Fixtures**: Use helper functions from `internal/testing`
4. **Assertions**: Use testify assertions for clear error messages
5. **Database**: Use transactions and rollback for faster tests

## Debugging

### Enable SQL Logging
```go
db.Logger = logger.Default.LogMode(logger.Info)
```

### Check Test Database
```bash
psql auth_test
\dt  # List tables
SELECT * FROM users WHERE tenant_id = '<test-tenant-id>';
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Run Integration Tests
  run: |
    docker-compose -f docker-compose.test.yml up -d
    make test-integration
  env:
    TEST_DB_HOST: localhost
    TEST_DB_PORT: 5432
```

## Troubleshooting

### Connection Refused
- Ensure PostgreSQL is running
- Check TEST_DB_* environment variables
- Verify database exists

### Migration Errors
- Run migrations manually: `make migrate-up`
- Check migration files in `migrations/`

### Permission Denied
- Grant permissions to test user
- Use superuser for tests (not recommended for production)
