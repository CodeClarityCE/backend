package analyzer

import (
	"fmt"

	"codeclarity.io/cli/internal/api"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	listPage    int
	listPerPage int
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List analyzers",
	Long:  `List all analyzers in the organization.`,
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

		resp, err := client.ListAnalyzers(orgID, listPage, listPerPage)
		if err != nil {
			output.Error("Failed to list analyzers: %v", err)
			return nil
		}

		if len(resp.Data) == 0 {
			output.Info("No analyzers found")
			return nil
		}

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "" {
			format = "table"
		}
		formatter := output.NewFormatter(format)

		headers := []string{"ID", "NAME", "DESCRIPTION", "LANGUAGES", "GLOBAL"}
		var rows [][]string

		for _, a := range resp.Data {
			languages := "-"
			if len(a.SupportedLanguages) > 0 {
				languages = fmt.Sprintf("%v", a.SupportedLanguages)
			}
			global := "No"
			if a.Global {
				global = "Yes"
			}
			rows = append(rows, []string{
				a.ID,
				a.Name,
				truncate(a.Description, 40),
				languages,
				global,
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
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
