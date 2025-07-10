.PHONY: build test lint docs clean install help

# Get the name of the provider from the directory
PROVIDER_NAME := stepsecurity

# Default target
.DEFAULT_GOAL := help

# Help target
help: ## Display this help
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the provider
	go build -v .

install: ## Install the provider locally
	go install .

test: ## Run tests
	go test -race ./...

testacc: ## Run acceptance tests
	TF_ACC=1 go test -race ./... -v

docs: ## Generate documentation
	go generate -tags tools tools/tools.go

lint: ## Run linters
	golangci-lint run ./... -v
