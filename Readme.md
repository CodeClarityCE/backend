<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)

<details open="open">
<summary>Table of Contents</summary>

- [CodeClarity Backend](#codeclarity-backend)
  - [Contributing](#contributing)
  - [Reporting Issues](#reporting-issues)

</details>

---

# CodeClarity Backend

## CLI

The module at the root of this repository is the `codeclarity` CLI, which a CI pipeline uses to analyse a project.
An organization admin creates an Organization token (scope `analyze`) on the instance's Organization tokens page.

```sh
export CODECLARITY_TOKEN=ccot_...
codeclarity login --url https://codeclarity.example.com/api --org <organization id>
codeclarity analyze . --analyzer "Default Analyzer" --timeout 20m
codeclarity results --format json > findings.json
codeclarity results --format sarif --fail-on high > codeclarity.sarif
```

- `login` checks the token and stores it in `~/.codeclarity/credentials.json` (mode 0600). A pipeline can skip it by
  setting `CODECLARITY_URL`, `CODECLARITY_ORG` and `CODECLARITY_TOKEN`; the variables override the stored login.
- `analyze` uploads the directory (without `.git`, `node_modules` and `vendor`) as a new project and starts an
  analysis. It prints the organization, project and analysis ids as JSON. It waits for the analysis to end and fails
  when the analysis fails or `--timeout` passes; `--no-wait` returns once the analysis has started.
- `analyze --project <id>` analyses a project already on the instance, such as one linked from GitHub or GitLab,
  without uploading anything: on its default branch, or on `--branch`. The instance fetches the code.
- `results` prints the findings of the last analysis, or of `--project` and `--analysis`, as `--format json`
  (default), `sarif` or `cyclonedx`.
- `--format sarif` writes SARIF 2.1.0 for GitHub code scanning: one alert per vulnerable dependency, located at the
  first line of `--manifest` (by default the first of `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
  `composer.lock`, `package.json`, `composer.json` in the working directory, which should be the repository root).
  Upload it with `github/codeql-action/upload-sarif`.
- `--format cyclonedx` prints the analysis's SBOM as CycloneDX 1.6 JSON instead, with every workspace unless
  `--workspace` names one; `--component-name` and `--component-version` name the analysed software in it.
- `results --fail-on <severity>` (`critical`, `high`, `medium`, `low` or `none`) still prints every finding, then exits
  with code 3 when one is at or above that severity. Every other error exits with code 1.
- An instance with a private CA: point `SSL_CERT_FILE` at the CA certificate.

## Contributing

If you'd like to contribute code or documentation, please see [CONTRIBUTING.md](https://github.com/CodeClarityCE/codeclarity-dev/blob/main/CONTRIBUTING.md) for guidelines on how to do so.

## Reporting Issues

Please report any issues with the setup process or other problems encountered while using this repository by opening a new issue in this project's GitHub page.
