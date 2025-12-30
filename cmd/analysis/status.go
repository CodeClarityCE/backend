package analysis

import (
	"fmt"
	"time"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/output"
	"github.com/spf13/cobra"
)

var statusWatch bool

var statusCmd = &cobra.Command{
	Use:   "status <project-id> <analysis-id>",
	Short: "Get analysis status",
	Long: `Get the status of an analysis.

Use --watch to continuously poll for updates until the analysis completes.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectID := args[0]
		analysisID := args[1]

		orgID := getOrgID(cmd)
		if orgID == "" {
			output.Error("Organization ID required. Use --org flag or set default with 'codeclarity config set org <id>'")
			return nil
		}

		client, err := api.NewAuthenticatedClient()
		if err != nil {
			output.Error("Authentication required: %v", err)
			return nil
		}

		if statusWatch {
			return watchAnalysisStatus(client, orgID, projectID, analysisID)
		}

		analysis, err := client.GetAnalysis(orgID, projectID, analysisID)
		if err != nil {
			output.Error("Failed to get analysis: %v", err)
			return nil
		}

		printAnalysisStatus(analysis)
		return nil
	},
}

func printAnalysisStatus(analysis *api.Analysis) {
	fmt.Printf("Analysis: %s\n", analysis.ID)
	fmt.Printf("Status:   %s\n", output.StatusColor(string(analysis.Status)))
	fmt.Printf("Branch:   %s\n", analysis.Branch)
	fmt.Printf("Stage:    %d\n", analysis.Stage)
	fmt.Printf("Created:  %s\n", analysis.CreatedOn.Format(time.RFC3339))

	if analysis.StartedOn != nil {
		fmt.Printf("Started:  %s\n", analysis.StartedOn.Format(time.RFC3339))
	}
	if analysis.EndedOn != nil {
		fmt.Printf("Ended:    %s\n", analysis.EndedOn.Format(time.RFC3339))
	}
	if analysis.CommitHash != "" {
		fmt.Printf("Commit:   %s\n", analysis.CommitHash)
	}
}

func watchAnalysisStatus(client *api.Client, orgID, projectID, analysisID string) error {
	fmt.Println("Watching analysis status (Ctrl+C to stop)...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastStatus := ""
	for {
		analysis, err := client.GetAnalysis(orgID, projectID, analysisID)
		if err != nil {
			output.Error("Failed to get analysis: %v", err)
			return nil
		}

		status := string(analysis.Status)
		if status != lastStatus {
			fmt.Printf("[%s] Status: %s (stage %d)\n",
				time.Now().Format("15:04:05"),
				output.StatusColor(status),
				analysis.Stage)
			lastStatus = status
		}

		// Check for terminal states
		switch analysis.Status {
		case api.StatusSuccess, api.StatusCompleted:
			output.Success("Analysis completed!")
			printAnalysisStatus(analysis)
			return nil
		case api.StatusFailed:
			output.Error("Analysis failed")
			printAnalysisStatus(analysis)
			return nil
		}

		<-ticker.C
	}
}

func init() {
	statusCmd.Flags().BoolVarP(&statusWatch, "watch", "w", false, "Watch for status changes")
}
