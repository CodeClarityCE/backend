package analysis

import (
	"codeclarity.io/internal/config"
	"github.com/spf13/cobra"
)

// AnalysisCmd represents the analysis command group
var AnalysisCmd = &cobra.Command{
	Use:   "analysis",
	Short: "Manage analyses",
	Long:  `Start, list, and manage security analyses.`,
}

func init() {
	AnalysisCmd.AddCommand(listCmd)
	AnalysisCmd.AddCommand(startCmd)
	AnalysisCmd.AddCommand(statusCmd)
	AnalysisCmd.AddCommand(getCmd)
}

// getOrgID returns the organization ID from flag or config
func getOrgID(cmd *cobra.Command) string {
	if orgID := cmd.Root().Flag("org").Value.String(); orgID != "" {
		return orgID
	}
	cfg, err := config.Load()
	if err != nil {
		return ""
	}
	return cfg.DefaultOrgID
}
