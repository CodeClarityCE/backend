package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/session"
	"github.com/spf13/cobra"
)

// analysisTarget is the analysis --project and --analysis name, or the last one analyze started.
func analysisTarget(project, analysis string) (session.Analysis, error) {
	target := session.Analysis{ProjectID: project, AnalysisID: analysis}
	if target.ProjectID != "" && target.AnalysisID != "" {
		return target, nil
	}
	if target.ProjectID != "" || target.AnalysisID != "" {
		return target, fmt.Errorf("pass both --project and --analysis, or neither")
	}
	return session.LastAnalysis()
}

// endedAnalysis reads the target analysis and refuses one that has no results yet.
func endedAnalysis(cmd *cobra.Command, client *api.Client, org string, target session.Analysis) (api.Analysis, error) {
	analysis, err := client.Analysis(cmd.Context(), org, target.ProjectID, target.AnalysisID)
	if err != nil {
		return analysis, fmt.Errorf("reading analysis %s: %w", target.AnalysisID, err)
	}
	if !finished(analysis.Status) {
		return analysis, fmt.Errorf("analysis %s is %s, so it has no results yet", target.AnalysisID, analysis.Status)
	}
	return analysis, nil
}

// printJSON writes v as indented JSON, as the results command does.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newAnalysesCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "analyses",
		Short: "List the analyses of a project",
		Long: `List the analyses of a project as JSON: id, status, branch, tag, commit and dates.
The project is --project, or the one the last analyze used.

  codeclarity analyses --project <project id>`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := session.Load()
			if err != nil {
				return err
			}
			if project == "" {
				last, err := session.LastAnalysis()
				if err != nil {
					return fmt.Errorf("pass --project: %w", err)
				}
				project = last.ProjectID
			}
			analyses, err := api.New(s.URL, s.Token).Analyses(cmd.Context(), s.OrganizationID, project)
			if err != nil {
				return fmt.Errorf("listing the analyses of project %s: %w", project, err)
			}
			if analyses == nil {
				analyses = []api.AnalysisSummary{}
			}
			return printJSON(cmd.OutOrStdout(), analyses)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project id (default: the last analyze's)")
	return cmd
}

// analysisFlags are the flags of the commands that read one analysis's results.
type analysisFlags struct {
	project   string
	analysis  string
	workspace string
}

func (f *analysisFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.project, "project", "", "project id (default: the last analyze's)")
	cmd.Flags().StringVar(&f.analysis, "analysis", "", "analysis id (default: the last analyze's)")
	cmd.Flags().StringVar(&f.workspace, "workspace", ".", "workspace of the project")
}

// open loads the session and checks the analysis has ended.
func (f *analysisFlags) open(cmd *cobra.Command) (session.Session, *api.Client, session.Analysis, error) {
	s, err := session.Load()
	if err != nil {
		return s, nil, session.Analysis{}, err
	}
	target, err := analysisTarget(f.project, f.analysis)
	if err != nil {
		return s, nil, target, err
	}
	client := api.New(s.URL, s.Token)
	if _, err := endedAnalysis(cmd, client, s.OrganizationID, target); err != nil {
		return s, nil, target, err
	}
	return s, client, target, nil
}

func newLicensesCmd() *cobra.Command {
	var f analysisFlags
	cmd := &cobra.Command{
		Use:   "licenses",
		Short: "Print the licenses of an analysis",
		Long: `Print as JSON the licenses an ended analysis found in a workspace, each with the
dependencies under it and whether it breaks the analysis's license policy: the last
analysis analyze started, or the one named by --project and --analysis.

  codeclarity licenses --workspace .`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, client, target, err := f.open(cmd)
			if err != nil {
				return err
			}
			licenses, err := client.Licenses(cmd.Context(), s.OrganizationID, target.ProjectID, target.AnalysisID, f.workspace)
			if err != nil {
				return fmt.Errorf("reading the licenses of analysis %s: %w", target.AnalysisID, err)
			}
			if licenses == nil {
				licenses = []json.RawMessage{}
			}
			return printJSON(cmd.OutOrStdout(), licenses)
		},
	}
	f.add(cmd)
	return cmd
}

func newExplainCmd() *cobra.Command {
	var f analysisFlags
	cmd := &cobra.Command{
		Use:   "explain <name@version>",
		Short: "Explain why a dependency is installed",
		Long: `Print as JSON one dependency of an ended analysis and the graph of dependencies that
lead to it from the workspace, so you can see which direct dependency pulls it in.

  codeclarity explain lodash@4.17.20
  codeclarity explain @babel/core@7.24.0 --workspace packages/web`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dependency := args[0]
			if at := strings.LastIndex(dependency, "@"); at <= 0 || at == len(dependency)-1 {
				return fmt.Errorf("name the dependency as name@version, such as lodash@4.17.20")
			}
			s, client, target, err := f.open(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			info, err := client.Dependency(ctx, s.OrganizationID, target.ProjectID, target.AnalysisID, f.workspace, dependency)
			if err != nil {
				return fmt.Errorf("reading %s in analysis %s: %w", dependency, target.AnalysisID, err)
			}
			graph, err := client.DependencyGraph(ctx, s.OrganizationID, target.ProjectID, target.AnalysisID, f.workspace, dependency)
			if err != nil {
				return fmt.Errorf("reading the graph of %s in analysis %s: %w", dependency, target.AnalysisID, err)
			}
			return printJSON(cmd.OutOrStdout(), map[string]json.RawMessage{"dependency": info, "graph": graph})
		},
	}
	f.add(cmd)
	return cmd
}

func newFixNextCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "fix-next",
		Short: "Print the upgrades that fix the most across the organization",
		Long: `Print as JSON the organization's remediations, the ones that fix the most first: the
package, its target version, whether the upgrade may break, and for each project the
command that applies it.

  codeclarity fix-next --limit 5`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > 50 {
				return fmt.Errorf("--limit must be between 1 and 50")
			}
			s, err := session.Load()
			if err != nil {
				return err
			}
			entries, err := api.New(s.URL, s.Token).FixNext(cmd.Context(), s.OrganizationID, limit)
			if err != nil {
				return fmt.Errorf("reading the remediations: %w", err)
			}
			return printJSON(cmd.OutOrStdout(), entries)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 10, "how many remediations to print, 1 to 50")
	return cmd
}

func newVulnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vuln <vulnerability id>",
		Short: "Describe a vulnerability and the projects it affects",
		Long: `Print as JSON what the instance knows of a vulnerability (description, severities,
EPSS, known exploitation, affected ranges) and the organization's projects it affects,
with their remediations.

  codeclarity vuln CVE-2021-23337`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := session.Load()
			if err != nil {
				return err
			}
			page, err := api.New(s.URL, s.Token).Vulnerability(cmd.Context(), s.OrganizationID, args[0])
			if err != nil {
				return fmt.Errorf("reading vulnerability %s: %w", args[0], err)
			}
			return printJSON(cmd.OutOrStdout(), page)
		},
	}
}
