package analysis

import (
	"fmt"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/output"
	"github.com/spf13/cobra"
)

var (
	listPage    int
	listPerPage int
)

var listCmd = &cobra.Command{
	Use:   "list <project-id>",
	Short: "List analyses for a project",
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

		resp, err := client.ListAnalyses(orgID, projectID, listPage, listPerPage)
		if err != nil {
			output.Error("Failed to list analyses: %v", err)
			return nil
		}

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "" {
			format = "table"
		}

		// For JSON/YAML output, return the raw API response
		if format == "json" || format == "yaml" {
			formatter := output.NewFormatter(format)
			return formatter.Print(resp)
		}

		if len(resp.Data) == 0 {
			output.Info("No analyses found")
			return nil
		}

		// Table output
		headers := []string{"ID", "STATUS", "BRANCH", "CREATED", "STAGE"}
		var rows [][]string

		for _, a := range resp.Data {
			stage := fmt.Sprintf("%d", a.Stage)
			rows = append(rows, []string{
				a.ID,
				output.StatusColor(string(a.Status)),
				a.Branch,
				a.CreatedOn.Format("2006-01-02 15:04"),
				stage,
			})
		}

		formatter := output.NewFormatter(format)
		formatter.PrintTable(headers, rows)

		if resp.TotalPages > 1 {
			fmt.Printf("\nPage %d of %d (total: %d)\n", resp.Page+1, resp.TotalPages, resp.TotalEntries)
		}

		return nil
	},
}

func init() {
	listCmd.Flags().IntVar(&listPage, "page", 0, "Page number (0-indexed)")
	listCmd.Flags().IntVar(&listPerPage, "per-page", 20, "Entries per page")
}
