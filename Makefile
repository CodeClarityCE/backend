# Makefile template derivated from https://github.com/dunglas/symfony-docker/blob/main/docs/makefile.md
.DEFAULT_GOAL = help
.PHONY        = help build build-prod up down logs cli-build cli-install cli-test cli-build-all

# CLI configuration
CLI_BINARY_NAME=codeclarity
CLI_VERSION?=0.1.0
CLI_BUILD_DIR=./bin
CLI_LDFLAGS=-ldflags "-X codeclarity.io/cmd.Version=$(CLI_VERSION)"

## —— 🦉 CodeClarity's backend 🦉 ——————————————————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

## —— Docker 🐳 ————————————————————————————————————————————————————————————————
build-prod: ## Builds de production Docker images
	@sh .cloud/docker/scripts/build-prod.sh

build: ## Builds the Docker images
	@cd ../.cloud/scripts && sh build.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-license-finder plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

up: ## Starts the Docker images
	@cd ../.cloud/scripts && sh up.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-license-finder plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

down: ## Stops the Docker images
	@cd ../.cloud/scripts && sh down.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-license-finder plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

logs: ## Display logs
	@cd ../.cloud/scripts && sh logs.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-license-finder plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

## —— CLI 🖥️ ————————————————————————————————————————————————————————————————
cli-build: ## Build the CLI binary
	go build $(CLI_LDFLAGS) -o $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME) .

cli-install: ## Install CLI to GOPATH/bin
	go build $(CLI_LDFLAGS) -o $(GOPATH)/bin/$(CLI_BINARY_NAME) .

cli-install-local: cli-build ## Install CLI to /usr/local/bin (requires sudo)
	sudo cp $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME) /usr/local/bin/$(CLI_BINARY_NAME)

cli-install-user: cli-build ## Install CLI to ~/.local/bin
	mkdir -p $(HOME)/.local/bin
	cp $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME) $(HOME)/.local/bin/$(CLI_BINARY_NAME)
	@echo "Installed to $(HOME)/.local/bin/$(CLI_BINARY_NAME)"

cli-clean: ## Clean CLI build artifacts
	go clean
	rm -rf $(CLI_BUILD_DIR)

cli-test: ## Run CLI tests
	go test -v ./...

cli-run: cli-build ## Build and run the CLI
	$(CLI_BUILD_DIR)/$(CLI_BINARY_NAME)

cli-deps: ## Download CLI dependencies
	go mod download
	go mod tidy

cli-fmt: ## Format CLI code
	go fmt ./...

cli-lint: ## Lint CLI code
	golangci-lint run

cli-build-all: cli-build-linux cli-build-darwin cli-build-windows ## Build CLI for all platforms

cli-build-linux: ## Build CLI for Linux
	GOOS=linux GOARCH=amd64 go build $(CLI_LDFLAGS) -o $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(CLI_LDFLAGS) -o $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME)-linux-arm64 .

cli-build-darwin: ## Build CLI for macOS
	GOOS=darwin GOARCH=amd64 go build $(CLI_LDFLAGS) -o $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(CLI_LDFLAGS) -o $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME)-darwin-arm64 .

cli-build-windows: ## Build CLI for Windows
	GOOS=windows GOARCH=amd64 go build $(CLI_LDFLAGS) -o $(CLI_BUILD_DIR)/$(CLI_BINARY_NAME)-windows-amd64.exe .