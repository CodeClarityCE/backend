package project

import (
	"fmt"

	"codeclarity.io/cli/internal/api"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	createURL           string
	createIntegrationID string
	createName          string
	createDescription   string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Import a new project",
	Long: `Import a new project from a Git repository.

Example:
  codeclarity project create --url https://github.com/org/repo --integration <integration-id>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID := getOrgID(cmd)
		if orgID == "" {
			output.Error("Organization ID required. Use --org flag or set default with 'codeclarity config set org <id>'")
			return nil
		}

		if createURL == "" {
			output.Error("Repository URL is required. Use --url")
			return nil
		}

		if createIntegrationID == "" {
			output.Error("Integration ID is required. Use --integration")
			return nil
		}

		client, err := api.NewAuthenticatedClient()
		if err != nil {
			output.Error("Authentication required: %v", err)
			return nil
		}

		req := api.ProjectImportRequest{
			IntegrationID: createIntegrationID,
			URL:           createURL,
			Name:          createName,
			Description:   createDescription,
		}

		id, err := client.ImportProject(orgID, req)
		if err != nil {
			output.Error("Failed to import project: %v", err)
			return nil
		}

		output.Success("Project imported: %s", id)
		fmt.Printf("ID: %s\n", id)

		return nil
	},
}

func init() {
	createCmd.Flags().StringVar(&createURL, "url", "", "Repository URL (required)")
	createCmd.Flags().StringVar(&createIntegrationID, "integration", "", "Integration ID (required)")
	createCmd.Flags().StringVar(&createName, "name", "", "Project name (optional)")
	createCmd.Flags().StringVar(&createDescription, "description", "", "Project description (optional)")
}
