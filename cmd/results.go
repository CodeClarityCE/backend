package cmd

import (
	"fmt"
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
}

func newResultsCmd() *cobra.Command {
	var o resultsOptions
	cmd := &cobra.Command{
		Use:   "results",
		Short: "Print the findings of an analysis",
		Long: `Print the findings of an ended analysis: the last one analyze started, or the one named
by --project and --analysis. --format cyclonedx writes the analysis's SBOM instead, of
every workspace unless --workspace names one.

  codeclarity results --format json > findings.json
  codeclarity results --format cyclonedx --component-name my-app --component-version v1.2.0 > sbom.cdx.json`,
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
	return report.Write(o.format, cmd.OutOrStdout(), r)
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
