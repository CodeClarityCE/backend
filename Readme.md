```
go mod tidy
export GOPRIVATE=github.com/CodeClarityCE/utility-types,github.com/CodeClarityCE/knowledge-database,github.com/CodeClarityCE/service-dispatcher,github.com/CodeClarityCE/service-project-downloader,github.com/CodeClarityCE/service-sbom,github.com/CodeClarityCE/service-sca-license,github.com/CodeClarityCE/spdx-license-matcher,github.com/CodeClarityCE/service-sca-patching,github.com/CodeClarityCE/service-sca-vuln-finder,github.com/CodeClarityCE/utility-node-semver,github.com/CodeClarityCE/plugin-sbom-javascript,github.com/CodeClarityCE/sbom-php,github.com/CodeClarityCE/utility-dbhelper,github.com/CodeClarityCE/amqp-helper
make build
```