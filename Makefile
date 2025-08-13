# Makefile template derivated from https://github.com/dunglas/symfony-docker/blob/main/docs/makefile.md
.DEFAULT_GOAL = help
.PHONY        = help build build-prod up down logs

## —— 🦉 CodeClarity's backend 🦉 ——————————————————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

## —— Docker 🐳 ————————————————————————————————————————————————————————————————
build-prod: ## Builds de production Docker images
	@sh .cloud/docker/scripts/build-prod.sh

build: ## Builds the Docker images
	@cd ../.cloud/scripts && sh build.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-js-license plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

up: ## Starts the Docker images
	@cd ../.cloud/scripts && sh up.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-js-license plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

down: ## Stops the Docker images
	@cd ../.cloud/scripts && sh down.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-js-license plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"

logs: ## Display logs
	@cd ../.cloud/scripts && sh logs.sh \
	"service-package-follower service-notifier service-downloader service-dispatcher service-scheduler plugin-codeql plugin-js-license plugin-js-patching plugin-js-sbom plugin-vuln-finder plugin-php-sbom"