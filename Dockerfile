# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/api ./cmd/api

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 orbguard

# Set working directory
WORKDIR /app

# Copy binary from builder (with correct ownership)
COPY --from=builder --chown=orbguard:orbguard /app/bin/api /app/api

# Copy config file (with correct ownership)
COPY --from=builder --chown=orbguard:orbguard /app/config.yaml /app/config.yaml

# Copy migrations (for running migrations in container)
COPY --from=builder --chown=orbguard:orbguard /app/migrations /app/migrations

# Copy rules (YARA rules)
COPY --from=builder --chown=orbguard:orbguard /app/rules /app/rules

# Copy MITRE data
COPY --from=builder --chown=orbguard:orbguard /app/data /app/data

# Switch to non-root user
USER orbguard

# Expose ports
EXPOSE 8090 9002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8090/health || exit 1

# Run the application
ENTRYPOINT ["/app/api"]
