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
	failOn    string
	manifest  string
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
by --project and --analysis.

With --fail-on, it still prints every finding, then exits with code 3 when one is at or
above that severity. Any other error exits with code 1.

  codeclarity results --format json > findings.json
  codeclarity results --format sarif --fail-on high > codeclarity.sarif

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
	target := session.Analysis{ProjectID: o.project, AnalysisID: o.analysis}
	if target.ProjectID == "" || target.AnalysisID == "" {
		if target.ProjectID != "" || target.AnalysisID != "" {
			return fmt.Errorf("pass both --project and --analysis, or neither")
		}
		if target, err = session.LastAnalysis(); err != nil {
			return err
		}
	}

	ctx := cmd.Context()
	client := api.New(s.URL, s.Token)
	analysis, err := client.Analysis(ctx, s.OrganizationID, target.ProjectID, target.AnalysisID)
	if err != nil {
		return fmt.Errorf("reading analysis %s: %w", target.AnalysisID, err)
	}
	if !finished(analysis.Status) {
		return fmt.Errorf("analysis %s is %s, so it has no results yet", target.AnalysisID, analysis.Status)
	}
	findings, err := client.Findings(ctx, s.OrganizationID, target.ProjectID, target.AnalysisID, o.workspace)
	if err != nil {
		return fmt.Errorf("reading the findings of analysis %s: %w", target.AnalysisID, err)
	}
	r := report.New(s.OrganizationID, target.ProjectID, analysis, findings)
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
