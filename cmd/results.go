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
}

func newResultsCmd() *cobra.Command {
	var o resultsOptions
	cmd := &cobra.Command{
		Use:   "results",
		Short: "Print the findings of an analysis",
		Long: `Print the findings of an ended analysis: the last one analyze started, or the one named
by --project and --analysis.

  codeclarity results --format json > findings.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return results(cmd, o)
		},
	}
	cmd.Flags().StringVar(&o.format, "format", "json", "output format: "+strings.Join(report.Formats(), ", "))
	cmd.Flags().StringVar(&o.project, "project", "", "project id (default: the last analyze's)")
	cmd.Flags().StringVar(&o.analysis, "analysis", "", "analysis id (default: the last analyze's)")
	cmd.Flags().StringVar(&o.workspace, "workspace", ".", "workspace of the project")
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
	return report.Write(o.format, cmd.OutOrStdout(), report.New(s.OrganizationID, target.ProjectID, analysis, findings))
}
