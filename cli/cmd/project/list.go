package project

import (
	"fmt"

	"codeclarity.io/cli/internal/api"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	listPage    int
	listPerPage int
	listSearch  string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List projects",
	Long:  `List all projects in the organization.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		resp, err := client.ListProjects(orgID, listPage, listPerPage, listSearch)
		if err != nil {
			output.Error("Failed to list projects: %v", err)
			return nil
		}

		if len(resp.Data) == 0 {
			output.Info("No projects found")
			return nil
		}

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "" {
			format = "table"
		}
		formatter := output.NewFormatter(format)

		headers := []string{"ID", "NAME", "URL", "BRANCH", "TYPE"}
		var rows [][]string

		for _, p := range resp.Data {
			rows = append(rows, []string{
				p.ID,
				p.Name,
				truncate(p.URL, 50),
				p.DefaultBranch,
				p.IntegrationProvider,
			})
		}

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
	listCmd.Flags().StringVar(&listSearch, "search", "", "Search filter")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
