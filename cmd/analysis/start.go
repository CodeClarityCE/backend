package analysis

import (
	"fmt"
	"time"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/output"
	"github.com/spf13/cobra"
)

var (
	startAnalyzerID string
	startBranch     string
	startCommit     string
	startTag        string
	startWatch      bool
)

var startCmd = &cobra.Command{
	Use:   "start <project-id>",
	Short: "Start a new analysis",
	Long: `Start a new security analysis for a project.

Example:
  codeclarity analysis start <project-id> --analyzer <analyzer-id> --branch main
  codeclarity analysis start <project-id> --analyzer <analyzer-id> --branch main --watch`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectID := args[0]

		orgID := getOrgID(cmd)
		if orgID == "" {
			output.Error("Organization ID required. Use --org flag or set default with 'codeclarity config set org <id>'")
			return nil
		}

		if startAnalyzerID == "" {
			output.Error("Analyzer ID is required. Use --analyzer")
			return nil
		}

		client, err := api.NewAuthenticatedClient()
		if err != nil {
			output.Error("Authentication required: %v", err)
			return nil
		}

		req := api.AnalysisCreateRequest{
			AnalyzerID:   startAnalyzerID,
			Branch:       startBranch,
			CommitHash:   startCommit,
			Tag:          startTag,
			Config:       make(map[string]map[string]any),
			ScheduleType: "once",
			IsActive:     true,
		}

		analysisID, err := client.StartAnalysis(orgID, projectID, req)
		if err != nil {
			output.Error("Failed to start analysis: %v", err)
			return nil
		}

		output.Success("Analysis started: %s", analysisID)

		if startWatch {
			return watchAnalysis(client, orgID, projectID, analysisID)
		}

		return nil
	},
}

func watchAnalysis(client *api.Client, orgID, projectID, analysisID string) error {
	fmt.Println("\nWatching analysis progress...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastStatus := ""
	for {
		analysis, err := client.GetAnalysis(orgID, projectID, analysisID)
		if err != nil {
			output.Error("Failed to get analysis status: %v", err)
			return nil
		}

		status := string(analysis.Status)
		if status != lastStatus {
			fmt.Printf("Status: %s (stage %d)\n", output.StatusColor(status), analysis.Stage)
			lastStatus = status
		}

		// Check for terminal states
		switch analysis.Status {
		case api.StatusSuccess, api.StatusCompleted:
			output.Success("Analysis completed successfully!")
			return nil
		case api.StatusFailed:
			output.Error("Analysis failed")
			return nil
		}

		<-ticker.C
	}
}

func init() {
	startCmd.Flags().StringVarP(&startAnalyzerID, "analyzer", "a", "", "Analyzer ID (required)")
	startCmd.Flags().StringVarP(&startBranch, "branch", "b", "main", "Branch to analyze")
	startCmd.Flags().StringVar(&startCommit, "commit", "", "Specific commit to analyze")
	startCmd.Flags().StringVar(&startTag, "tag", "", "Git tag to analyze")
	startCmd.Flags().BoolVarP(&startWatch, "watch", "w", false, "Watch analysis progress")
}
