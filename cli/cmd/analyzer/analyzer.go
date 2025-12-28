package analyzer

import (
	"codeclarity.io/cli/internal/config"
	"github.com/spf13/cobra"
)

// AnalyzerCmd represents the analyzer command group
var AnalyzerCmd = &cobra.Command{
	Use:   "analyzer",
	Short: "Manage analyzers",
	Long:  `Create, list, and manage analyzer configurations.`,
}

func init() {
	AnalyzerCmd.AddCommand(listCmd)
	AnalyzerCmd.AddCommand(createCmd)
	AnalyzerCmd.AddCommand(getCmd)
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
