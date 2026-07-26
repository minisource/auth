# Build stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy auth backend files including vendor
COPY auth/backend ./

# Build binary offline using self-contained vendor
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -ldflags="-w -s" -o /auth-server ./cmd/main.go

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN sed -i 's/https/http/g' /etc/apk/repositories && apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy binary from builder
COPY --from=builder /auth-server /app/auth-server

# Copy config files
COPY auth/backend/.env.example /app/.env.example

# Create logs directory
RUN mkdir -p /app/logs && chown -R appuser:appgroup /app

USER appuser

EXPOSE 9001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9001/health || exit 1

ENTRYPOINT ["/app/auth-server"]
