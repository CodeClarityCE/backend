package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/archive"
	"codeclarity.io/internal/session"
	"github.com/spf13/cobra"
)

// Waiting polls after pollFirst, then twice as long each time up to pollMax.
// Every poll writes an Audit log entry, so polls are few.
const (
	defaultPollFirst = 5 * time.Second
	defaultPollMax   = 30 * time.Second
)

var pollFirst, pollMax = defaultPollFirst, defaultPollMax

// uploadBranch is the directory an uploaded archive is unpacked into.
const uploadBranch = "main"

// What the web app sends for each kind of plugin.
var (
	vulnPlugins    = map[string]bool{"vuln-finder": true, "js-vuln-finder": true}
	licensePlugins = map[string]bool{"license-finder": true, "js-license": true}
)

type analyzeOptions struct {
	analyzer string
	name     string
	wait     bool
	noWait   bool
	timeout  time.Duration
	project  string
	branch   string
}

func newAnalyzeCmd() *cobra.Command {
	var o analyzeOptions
	cmd := &cobra.Command{
		Use:   "analyze [<directory> | --project <id>]",
		Short: "Upload a directory, or name a linked project, and analyse it",
		Long: `Upload a directory as a new project, or name a project already on the instance
(such as one linked from GitHub or GitLab), and start an analysis of it.

.git, node_modules and vendor are left out of an upload; the lockfiles are what the analysis reads.
A linked project is analysed on its default branch, or on --branch; the instance fetches it.
It waits for the analysis to end, and fails if it failed or --timeout passed; --no-wait returns once it starts.
It prints the organization, project and analysis ids as JSON, and remembers them for results.

  codeclarity analyze . --analyzer "Default Analyzer" --timeout 20m
  codeclarity analyze --project <project id> --branch main --no-wait`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.wait = !o.noWait
			switch {
			case len(args) == 1 && o.project != "":
				return fmt.Errorf("pass a directory or --project, not both")
			case len(args) == 1 && o.branch != "":
				return fmt.Errorf("--branch is for a linked project; an upload has no branches")
			case len(args) == 1:
				return analyze(cmd, args[0], o)
			case o.project != "":
				return analyzeProject(cmd, o)
			default:
				return fmt.Errorf("pass the directory to upload, or --project with the id of a linked project")
			}
		},
	}
	cmd.Flags().StringVar(&o.analyzer, "analyzer", "Default Analyzer", "name or id of the analyzer to run")
	cmd.Flags().StringVar(&o.name, "name", "", "project name (default: the directory's name)")
	// --wait is the default; the flag stays so existing pipelines keep working.
	cmd.Flags().BoolVar(&o.wait, "wait", true, "wait for the analysis to end (the default)")
	cmd.Flags().BoolVar(&o.noWait, "no-wait", false, "return once the analysis has started")
	cmd.MarkFlagsMutuallyExclusive("wait", "no-wait")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 30*time.Minute, "how long to wait for the analysis")
	cmd.Flags().StringVar(&o.project, "project", "", "id of a project on the instance to analyse instead of an upload")
	cmd.Flags().StringVar(&o.branch, "branch", "", "branch of the --project to analyse (default: its default branch)")
	return cmd
}

func analyze(cmd *cobra.Command, dir string, o analyzeOptions) error {
	s, err := session.Load()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	client := api.New(s.URL, s.Token)
	org := s.OrganizationID

	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	name := o.name
	if name == "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		name = filepath.Base(abs)
	}

	analyzer, err := findAnalyzer(ctx, client, org, o.analyzer)
	if err != nil {
		return err
	}
	zipped, err := archive.Zip(dir)
	if err != nil {
		return fmt.Errorf("packing %s: %w", dir, err)
	}
	projectID, err := client.CreateUploadProject(ctx, org, name, "Uploaded by the CodeClarity CLI")
	if err != nil {
		return writeRefused("create the project", err)
	}
	if err := client.UploadArchive(ctx, org, projectID, "source.zip", zipped); err != nil {
		return writeRefused("upload the directory", err)
	}
	return start(cmd, client, org, analyzer, projectID, name, uploadBranch, o)
}

// analyzeProject analyses a project already on the instance, without uploading anything.
func analyzeProject(cmd *cobra.Command, o analyzeOptions) error {
	s, err := session.Load()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	client := api.New(s.URL, s.Token)
	org := s.OrganizationID

	project, err := client.Project(ctx, org, o.project)
	if err != nil {
		return fmt.Errorf("reading project %s: %w", o.project, err)
	}
	branch := o.branch
	switch {
	case branch != "":
	case project.Type == "FILE" || project.DefaultBranch == "":
		// An upload is unpacked into one directory, whatever its default branch says.
		branch = uploadBranch
	default:
		branch = project.DefaultBranch
	}
	analyzer, err := findAnalyzer(ctx, client, org, o.analyzer)
	if err != nil {
		return err
	}
	return start(cmd, client, org, analyzer, project.ID, project.Name, branch, o)
}

// start starts the analysis of a project's branch, records it for results, and waits if asked.
func start(cmd *cobra.Command, client *api.Client, org string, analyzer api.Analyzer, projectID, name, branch string, o analyzeOptions) error {
	ctx := cmd.Context()
	analysisID, err := client.StartAnalysis(ctx, org, projectID, api.AnalysisStart{
		AnalyzerID: analyzer.ID,
		Branch:     branch,
		Config:     pluginConfig(analyzer, org, projectID, branch),
	})
	if err != nil {
		return writeRefused("start the analysis", err)
	}
	if err := session.SaveLastAnalysis(session.Analysis{ProjectID: projectID, AnalysisID: analysisID}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Started analysis %s of project %s (%s) with %s\n", analysisID, name, branch, analyzer.Name)

	status := "requested"
	if o.wait {
		var err error
		if status, err = waitFor(ctx, cmd, client, org, projectID, analysisID, o.timeout); err != nil {
			return err
		}
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{
		"organization_id": org,
		"project_id":      projectID,
		"analysis_id":     analysisID,
		"status":          status,
	})
}

// findAnalyzer picks the analyzer with that id or name.
func findAnalyzer(ctx context.Context, client *api.Client, org, wanted string) (api.Analyzer, error) {
	analyzers, err := client.Analyzers(ctx, org)
	if err != nil {
		return api.Analyzer{}, fmt.Errorf("listing analyzers: %w", err)
	}
	var names []string
	for _, a := range analyzers {
		if a.ID == wanted || a.Name == wanted {
			return a, nil
		}
		names = append(names, fmt.Sprintf("%q", a.Name))
	}
	return api.Analyzer{}, fmt.Errorf("no analyzer %q; the organization has %s", wanted, strings.Join(names, ", "))
}

// pluginConfig configures each plugin that takes options, as the web app does by default.
func pluginConfig(analyzer api.Analyzer, org, projectID, branch string) map[string]map[string]any {
	source := fmt.Sprintf("%s/projects/%s/%s", org, projectID, branch)
	config := map[string]map[string]any{}
	for _, stage := range analyzer.Steps {
		for _, plugin := range stage {
			if len(plugin.Config) == 0 {
				continue
			}
			switch {
			case strings.HasSuffix(plugin.Name, "-sbom"):
				config[plugin.Name] = map[string]any{"branch": branch, "project": source}
			case vulnPlugins[plugin.Name]:
				config["vuln-finder"] = map[string]any{"vulnerabilityPolicy": []string{}}
			case licensePlugins[plugin.Name]:
				config["license-finder"] = map[string]any{"licensePolicy": []string{}}
			case plugin.Name == "codeql":
				config[plugin.Name] = map[string]any{"project": source}
			default:
				config[plugin.Name] = map[string]any{}
			}
		}
	}
	return config
}

// writeRefused explains a refused write, which a read-only token gets.
func writeRefused(action string, err error) error {
	if api.IsStatus(err, http.StatusForbidden) {
		return fmt.Errorf("could not %s: the token needs the analyze scope in this organization: %w", action, err)
	}
	return fmt.Errorf("could not %s: %w", action, err)
}

// waitFor polls the analysis until it ends and returns its final status.
func waitFor(ctx context.Context, cmd *cobra.Command, client *api.Client, org, projectID, analysisID string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	status, last := "requested", ""
	for delay := pollFirst; ; delay = min(2*delay, pollMax) {
		select {
		case <-ctx.Done():
			return status, &exitError{code: 1, err: fmt.Errorf("analysis %s is still %s after %s", analysisID, status, timeout)}
		case <-time.After(delay):
		}
		analysis, err := client.Analysis(ctx, org, projectID, analysisID)
		if errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			return status, fmt.Errorf("reading analysis %s: %w", analysisID, err)
		}
		status = analysis.Status
		if status != last {
			fmt.Fprintf(cmd.ErrOrStderr(), "Analysis %s: %s\n", analysisID, status)
			last = status
		}
		switch {
		case finished(status):
			return status, nil
		case failed(status):
			return status, fmt.Errorf("analysis %s %s", analysisID, status)
		}
	}
}

func finished(status string) bool {
	return status == "completed" || status == "finished" || status == "success"
}

func failed(status string) bool {
	return status == "failed" || status == "failure" || status == "cancelled"
}
