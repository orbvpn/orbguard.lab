.PHONY: all build run test clean proto migrate lint docker help

# Variables
APP_NAME := orbguard-lab
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO := go
GOFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Directories
CMD_DIR := ./cmd
BIN_DIR := ./bin
PROTO_DIR := ./proto

# Default target
all: build

# Build the application
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/api $(CMD_DIR)/api
	@echo "Build complete: $(BIN_DIR)/api"

# Build for production (static binary)
build-prod:
	@echo "Building $(APP_NAME) for production..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/api-linux $(CMD_DIR)/api
	@echo "Build complete: $(BIN_DIR)/api-linux"

# Run the application
run:
	$(GO) run $(CMD_DIR)/api/main.go

# Run with hot reload (requires air)
dev:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/air-verse/air@latest)
	air -c .air.toml

# Run tests
test:
	$(GO) test -v -race ./...

# Run tests with coverage
test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go-grpc_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/threatintel/v1/*.proto
	@echo "Protobuf generation complete"

# Generate sqlc code
sqlc:
	@echo "Generating sqlc code..."
	@which sqlc > /dev/null || (echo "Installing sqlc..." && go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest)
	sqlc generate
	@echo "sqlc generation complete"

# Run database migrations
migrate-up:
	@echo "Running migrations..."
	@which goose > /dev/null || (echo "Installing goose..." && go install github.com/pressly/goose/v3/cmd/goose@latest)
	goose -dir ./migrations postgres "$(DATABASE_URL)" up

migrate-down:
	goose -dir ./migrations postgres "$(DATABASE_URL)" down

migrate-status:
	goose -dir ./migrations postgres "$(DATABASE_URL)" status

migrate-create:
	@read -p "Migration name: " name; \
	goose -dir ./migrations create $$name sql

# Lint code
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

# Format code
fmt:
	$(GO) fmt ./...
	@which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

# Download dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Update dependencies
deps-update:
	$(GO) get -u ./...
	$(GO) mod tidy

# Docker build
docker-build:
	docker build -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

# Docker run
docker-run:
	docker run -p 8090:8090 -p 9002:9002 $(APP_NAME):latest

# Docker compose up
docker-up:
	docker-compose up -d

# Docker compose down
docker-down:
	docker-compose down

# Docker compose logs
docker-logs:
	docker-compose logs -f

# Show help
help:
	@echo "OrbGuard Lab - Threat Intelligence Platform"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the application"
	@echo "  build-prod     Build static binary for production"
	@echo "  run            Run the application"
	@echo "  dev            Run with hot reload (requires air)"
	@echo "  test           Run tests"
	@echo "  test-coverage  Run tests with coverage"
	@echo "  clean          Clean build artifacts"
	@echo "  proto          Generate protobuf code"
	@echo "  sqlc           Generate sqlc code"
	@echo "  migrate-up     Run database migrations"
	@echo "  migrate-down   Rollback last migration"
	@echo "  migrate-status Show migration status"
	@echo "  migrate-create Create a new migration"
	@echo "  lint           Run linter"
	@echo "  fmt            Format code"
	@echo "  deps           Download dependencies"
	@echo "  deps-update    Update dependencies"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-run     Run Docker container"
	@echo "  docker-up      Start with docker-compose"
	@echo "  docker-down    Stop docker-compose"
	@echo "  docker-logs    Show docker-compose logs"
	@echo "  help           Show this help"
