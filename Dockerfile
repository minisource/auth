# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go.mod and go.sum first for better caching
COPY auth/go.mod auth/go.sum ./auth/
COPY go-common/ ./go-common/
COPY go-sdk/ ./go-sdk/

WORKDIR /app/auth

# Download dependencies
RUN go mod download

# Copy source code
COPY auth/ ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/auth-server ./cmd/main.go

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy binary from builder
COPY --from=builder /app/auth-server /app/auth-server

# Copy config files
COPY auth/.env.example /app/.env.example

# Create logs directory
RUN mkdir -p /app/logs && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/auth-server"]
