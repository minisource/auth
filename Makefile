# ================================
# Auth Service Makefile
# ================================

.PHONY: all build run test clean migrate migrate-up migrate-down migrate-create migrate-status migrate-force docker-build docker-up docker-down

# Variables
APP_NAME=auth
BINARY=bin/$(APP_NAME)
MIGRATE_BINARY=bin/migrate
GO=go
DOCKER_COMPOSE=docker compose

# ================================
# Build Commands
# ================================

all: build

build:
	@echo "Building $(APP_NAME)..."
	$(GO) build -o $(BINARY) ./cmd/main.go

build-migrate:
	@echo "Building migration tool..."
	$(GO) build -o $(MIGRATE_BINARY) ./cmd/migrate/main.go

run: build
	@echo "Running $(APP_NAME)..."
	./$(BINARY)

clean:
	@echo "Cleaning..."
	rm -rf bin/
	$(GO) clean

# ================================
# Test Commands
# ================================

test:
	$(GO) test -v ./...

test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# ================================
# Migration Commands
# ================================

# Apply all pending migrations
migrate: migrate-up

migrate-up: build-migrate
	@echo "Applying migrations..."
	./$(MIGRATE_BINARY) up

# Rollback last migration
migrate-down: build-migrate
	@echo "Rolling back last migration..."
	./$(MIGRATE_BINARY) down 1

# Rollback all migrations
migrate-down-all: build-migrate
	@echo "Rolling back all migrations..."
	./$(MIGRATE_BINARY) down $(shell ls -1 migrations/*.up.sql 2>/dev/null | wc -l)

# Show migration status
migrate-status: build-migrate
	@echo "Migration status..."
	./$(MIGRATE_BINARY) status

# Show current version
migrate-version: build-migrate
	./$(MIGRATE_BINARY) version

# Create new migration
# Usage: make migrate-create name=add_new_table
migrate-create: build-migrate
	@if [ -z "$(name)" ]; then \
		echo "Error: Please provide migration name: make migrate-create name=your_migration_name"; \
		exit 1; \
	fi
	./$(MIGRATE_BINARY) create $(name)

# Force migration version (for fixing dirty state)
# Usage: make migrate-force version=1
migrate-force: build-migrate
	@if [ -z "$(version)" ]; then \
		echo "Error: Please provide version: make migrate-force version=1"; \
		exit 1; \
	fi
	./$(MIGRATE_BINARY) force $(version)

# ================================
# Docker Commands
# ================================

docker-build:
	docker build -t $(APP_NAME):latest .

docker-up:
	$(DOCKER_COMPOSE) up -d

docker-up-dev:
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml up -d

docker-down:
	$(DOCKER_COMPOSE) down

docker-down-dev:
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml down

docker-logs:
	$(DOCKER_COMPOSE) logs -f $(APP_NAME)

docker-logs-dev:
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml logs -f $(APP_NAME)

# ================================
# Database Commands (Docker)
# ================================

db-shell:
	docker exec -it auth_postgres psql -U auth_user -d auth_db

db-shell-dev:
	docker exec -it auth_postgres_dev psql -U auth_user -d auth_db

# ================================
# Development Commands
# ================================

dev:
	@echo "Starting development mode..."
	@echo "Running: go run ./cmd/main.go"
	@$(GO) run ./cmd/main.go

# Install development tools
tools:
	$(GO) install github.com/cosmtrek/air@latest
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install github.com/golang-migrate/migrate/v4/cmd/migrate@latest

lint:
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...

# ================================
# Protobuf Commands
# ================================

# Generate protobuf files with buf (recommended)
proto-buf:
	@echo "Generating protobuf files with buf..."
	cd proto && buf generate

# Generate protobuf files with protoc (alternative)
proto-protoc:
	@echo "Generating protobuf files with protoc..."
	@if ! command -v protoc >/dev/null 2>&1; then \
		echo "Error: protoc is not installed. Run 'make proto-install' first."; \
		exit 1; \
	fi
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/auth/v1/*.proto

# Install protobuf tools
proto-install:
	@echo "Installing protobuf tools..."
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	$(GO) install github.com/bufbuild/buf/cmd/buf@latest
	@echo "✓ Protobuf tools installed"
	@echo "Note: You may also need to install protoc separately:"
	@echo "  - macOS: brew install protobuf"
	@echo "  - Linux: apt-get install protobuf-compiler"
	@echo "  - Windows: choco install protoc or download from https://github.com/protocolbuffers/protobuf/releases"

# Clean generated protobuf files
proto-clean:
	@echo "Cleaning generated protobuf files..."
	find proto -name "*.pb.go" -type f -delete
	@echo "✓ Cleaned"

# ================================
# Help
# ================================

help:
	@echo "Auth Service Makefile Commands"
	@echo ""
	@echo "Build:"
	@echo "  make build          - Build the application"
	@echo "  make run            - Build and run the application"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Test:"
	@echo "  make test           - Run tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo ""
	@echo "Migrations:"
	@echo "  make migrate-up     - Apply all pending migrations"
	@echo "  make migrate-down   - Rollback last migration"
	@echo "  make migrate-status - Show migration status"
	@echo "  make migrate-create name=<name> - Create new migration"
	@echo "  make migrate-force version=<n> - Force migration version"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-up      - Start with docker-compose"
	@echo "  make docker-up-dev  - Start development environment"
	@echo "  make docker-down    - Stop containers"
	@echo ""
	@echo "Development:"
	@echo "  make dev            - Run with hot reload (requires air)"
	@echo "  make tools          - Install development tools"
	@echo "  make lint           - Run linter"
	@echo ""
	@echo "Protobuf:"
	@echo "  make proto-buf      - Generate protobuf files with buf"
	@echo "  make proto-protoc   - Generate protobuf files with protoc"
	@echo "  make proto-install  - Install protobuf generation tools"
	@echo "  make proto-clean    - Remove generated protobuf files"
