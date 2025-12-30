package project

import (
	"codeclarity.io/internal/config"
	"github.com/spf13/cobra"
)

// ProjectCmd represents the project command group
var ProjectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects",
	Long:  `Create, list, and manage projects.`,
}

func init() {
	ProjectCmd.AddCommand(listCmd)
	ProjectCmd.AddCommand(createCmd)
	ProjectCmd.AddCommand(getCmd)
}

// getOrgID returns the organization ID from flag or config
func getOrgID(cmd *cobra.Command) string {
	// Check flag first
	if orgID := cmd.Root().Flag("org").Value.String(); orgID != "" {
		return orgID
	}
	// Fall back to config
	cfg, err := config.Load()
	if err != nil {
		return ""
	}
	return cfg.DefaultOrgID
}
