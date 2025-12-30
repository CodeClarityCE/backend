package result

import (
	"fmt"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/output"
	"github.com/spf13/cobra"
)

var vulnsWorkspace string
var vulnsPage int
var vulnsPerPage int

var vulnerabilitiesCmd = &cobra.Command{
	Use:   "vulnerabilities <project-id> <analysis-id>",
	Short: "List vulnerabilities",
	Long:  `List vulnerabilities found in an analysis.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectID := args[0]
		analysisID := args[1]

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

		vulns, err := client.GetVulnerabilities(orgID, projectID, analysisID, vulnsWorkspace, vulnsPage, vulnsPerPage)
		if err != nil {
			output.Error("Failed to get vulnerabilities: %v", err)
			return nil
		}

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "json" || format == "yaml" {
			formatter := output.NewFormatter(format)
			return formatter.Print(vulns)
		}

		// Table output
		if len(vulns.Data) == 0 {
			output.Success("No vulnerabilities found")
			return nil
		}

		fmt.Printf("Found %d vulnerabilities (page %d of %d)\n\n", vulns.TotalEntries, vulns.Page+1, vulns.TotalPages)

		headers := []string{"ID", "Severity", "CVSS", "Package", "Version", "Description"}
		var rows [][]string

		for _, v := range vulns.Data {
			// Get first affected package info
			pkgName := "-"
			pkgVersion := "-"
			if len(v.Affected) > 0 {
				pkgName = v.Affected[0].AffectedDependency
				pkgVersion = v.Affected[0].AffectedVersion
			}

			// Truncate description
			desc := v.Description
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}

			row := []string{
				v.ID,
				output.SeverityColor(v.Severity.SeverityClass),
				fmt.Sprintf("%.1f", v.Severity.Severity),
				pkgName,
				pkgVersion,
				desc,
			}
			rows = append(rows, row)
		}

		formatter := output.NewFormatter("table")
		formatter.PrintTable(headers, rows)

		return nil
	},
}

func init() {
	vulnerabilitiesCmd.Flags().StringVar(&vulnsWorkspace, "workspace", "", "Filter by workspace")
	vulnerabilitiesCmd.Flags().IntVar(&vulnsPage, "page", 0, "Page number (0-indexed)")
	vulnerabilitiesCmd.Flags().IntVar(&vulnsPerPage, "per-page", 20, "Results per page")
}
