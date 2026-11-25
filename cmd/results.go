package cmd

import (
	"fmt"
	"os"
	"strings"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/report"
	"codeclarity.io/internal/session"
	"github.com/spf13/cobra"
)

type resultsOptions struct {
	format    string
	project   string
	analysis  string
	workspace string
	// Name and version of the analysed software in an SBOM.
	componentName    string
	componentVersion string
	failOn           string
	manifest         string
}

// manifests are the files SARIF results point at by default, the first one the checkout has.
var manifests = []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "package.json", "composer.json"}

// exitFindings is the exit code of results when --fail-on finds a finding.
const exitFindings = 3

func newResultsCmd() *cobra.Command {
	var o resultsOptions
	cmd := &cobra.Command{
		Use:   "results",
		Short: "Print the findings of an analysis",
		Long: `Print the findings of an ended analysis: the last one analyze started, or the one named
by --project and --analysis. --format cyclonedx writes the analysis's SBOM instead, of
every workspace unless --workspace names one.

With --fail-on, it still prints every finding, then exits with code 3 when one is at or
above that severity. Any other error exits with code 1.

  codeclarity results --format json > findings.json
  codeclarity results --format sarif --fail-on high > codeclarity.sarif
  codeclarity results --format cyclonedx --component-name my-app --component-version v1.2.0 > sbom.cdx.json

SARIF results point at --manifest, by default the first of ` + strings.Join(manifests, ", ") + `
in the working directory, which should be the repository root.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return results(cmd, o)
		},
	}
	cmd.Flags().StringVar(&o.format, "format", "json", "output format: "+strings.Join(report.Formats(), ", "))
	cmd.Flags().StringVar(&o.project, "project", "", "project id (default: the last analyze's)")
	cmd.Flags().StringVar(&o.analysis, "analysis", "", "analysis id (default: the last analyze's)")
	cmd.Flags().StringVar(&o.workspace, "workspace", ".", "workspace of the project")
	cmd.Flags().StringVar(&o.componentName, "component-name", "", "name of the analysed software in an SBOM (default: the project id)")
	cmd.Flags().StringVar(&o.componentVersion, "component-version", "", "version of the analysed software in an SBOM")
	cmd.Flags().StringVar(&o.manifest, "manifest", "", "sarif: the file results point at, relative to the repository root")
	cmd.Flags().StringVar(&o.failOn, "fail-on", "", "exit with code 3 when a finding is at or above this severity: "+strings.Join(report.Severities, ", "))
	return cmd
}

func results(cmd *cobra.Command, o resultsOptions) error {
	s, err := session.Load()
	if err != nil {
		return err
	}
	// Check the format before any request.
	if err := report.Check(o.format); err != nil {
		return err
	}
	if o.failOn != "" {
		if err := report.CheckSeverity(o.failOn); err != nil {
			return err
		}
	}
	options := report.Options{Manifest: o.manifest, ToolVersion: Version}
	if o.format == "sarif" && options.Manifest == "" {
		if options.Manifest, err = findManifest(); err != nil {
			return err
		}
	}
	target, err := analysisTarget(o.project, o.analysis)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	client := api.New(s.URL, s.Token)
	analysis, err := endedAnalysis(cmd, client, s.OrganizationID, target)
	if err != nil {
		return err
	}
	findings, err := client.Findings(ctx, s.OrganizationID, target.ProjectID, target.AnalysisID, o.workspace)
	if err != nil {
		return fmt.Errorf("reading the findings of analysis %s: %w", target.AnalysisID, err)
	}
	r := report.New(s.OrganizationID, target.ProjectID, analysis, findings)
	if report.NeedsSBOM(o.format) {
		workspaces := []string{o.workspace}
		if !cmd.Flags().Changed("workspace") {
			workspaces = nil
		}
		if r.SBOM, err = readSBOM(cmd, client, s.OrganizationID, target, workspaces); err != nil {
			return fmt.Errorf("reading the SBOM of analysis %s: %w", target.AnalysisID, err)
		}
		r.SBOM.Name, r.SBOM.Version = o.componentName, o.componentVersion
	}
	if err := report.Write(o.format, cmd.OutOrStdout(), r, options); err != nil {
		return err
	}
	if o.failOn == "" {
		return nil
	}
	if n := r.AtOrAbove(o.failOn); n > 0 {
		return &exitError{code: exitFindings, err: fmt.Errorf("%d %s at or above %s", n, plural(n, "finding"), o.failOn)}
	}
	return nil
}

// readSBOM reads the dependencies of the named workspaces, or of every workspace when none are named.
func readSBOM(cmd *cobra.Command, client *api.Client, org string, target session.Analysis, workspaces []string) (*report.SBOM, error) {
	ctx := cmd.Context()
	if workspaces == nil {
		var err error
		if workspaces, err = client.SBOMWorkspaces(ctx, org, target.ProjectID, target.AnalysisID); err != nil {
			return nil, err
		}
	}
	sbom := &report.SBOM{ToolVersion: Version}
	for _, workspace := range workspaces {
		deps, err := client.Dependencies(ctx, org, target.ProjectID, target.AnalysisID, workspace)
		if err != nil {
			return nil, fmt.Errorf("workspace %s: %w", workspace, err)
		}
		sbom.Dependencies = append(sbom.Dependencies, deps...)
	}
	return sbom, nil
}

// findManifest picks the first manifest in the working directory.
func findManifest() (string, error) {
	for _, name := range manifests {
		if info, err := os.Stat(name); err == nil && info.Mode().IsRegular() {
			return name, nil
		}
	}
	return "", fmt.Errorf("no %s here: pass --manifest with the file SARIF results point at", strings.Join(manifests, ", "))
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
