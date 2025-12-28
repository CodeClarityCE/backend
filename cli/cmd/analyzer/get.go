package analyzer

import (
	"codeclarity.io/cli/internal/api"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <analyzer-id>",
	Short: "Get analyzer details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		analyzerID := args[0]

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

		analyzer, err := client.GetAnalyzer(orgID, analyzerID)
		if err != nil {
			output.Error("Failed to get analyzer: %v", err)
			return nil
		}

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "" {
			format = "yaml"
		}
		formatter := output.NewFormatter(format)
		return formatter.Print(analyzer)
	},
}
