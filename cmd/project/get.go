package project

import (
	"codeclarity.io/internal/api"
	"codeclarity.io/internal/output"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <project-id>",
	Short: "Get project details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectID := args[0]

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

		project, err := client.GetProject(orgID, projectID)
		if err != nil {
			output.Error("Failed to get project: %v", err)
			return nil
		}

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "" {
			format = "yaml"
		}
		formatter := output.NewFormatter(format)
		return formatter.Print(project)
	},
}
