package result

import (
	"codeclarity.io/internal/config"
	"github.com/spf13/cobra"
)

// ResultCmd represents the result command group
var ResultCmd = &cobra.Command{
	Use:   "result",
	Short: "View analysis results",
	Long:  `View vulnerability, SBOM, and license results from analyses.`,
}

func init() {
	ResultCmd.AddCommand(summaryCmd)
	ResultCmd.AddCommand(vulnerabilitiesCmd)
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
