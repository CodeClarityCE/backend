# Misc
.DEFAULT_GOAL = help

## —— SecuBox Makefile ——————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

## —— 📦 K8s deploy ——————————————————————————————————————
clean: ## Clean k8s cluster
	kubectl delete all --all --all-namespaces

postgresql-get-secrets: ## Get postgresql secrets
	@kubectl get secret --namespace default codeclarity-postgresql -o jsonpath="{.data.postgres-password}" | base64 -d
	@echo

rabbitmq-get-secrets: ## Get rabbitmq secrets
	@kubectl -n default get secret rabbitmq-default-user -o jsonpath="{.data.username}" | base64 --decode
	@echo
	@kubectl -n default get secret rabbitmq-default-user -o jsonpath="{.data.password}" | base64 --decode
	@echo

## —— ⎈ Helm chart Codeclarity ——————————————————————————
codeclarity-install: ## Deploy codeclarity backend
	helm install codeclarity codeclarity

codeclarity-upgrade: ## Upgrade codeclarity backend
	helm upgrade codeclarity codeclarity

codeclarity-uninstall: ## Uninstall codeclarity backend
	helm uninstall codeclarity
	kubectl delete statefulset rabbitmq-server

## —— ⎈ Kubernetes config ———————————————————————————————
k8s-config: ## Get k8s config
	@kubectl create secret docker-registry regcred --docker-server=docker.io --docker-username=<UID> --docker-password=<PWD> --docker-email=<EMAIL>