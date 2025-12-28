package result

import (
	"fmt"

	"codeclarity.io/cli/internal/api"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
)

var summaryWorkspace string

var summaryCmd = &cobra.Command{
	Use:   "summary <project-id> <analysis-id>",
	Short: "Get result summary",
	Long: `Get a summary of analysis results including vulnerabilities,
dependencies, and licenses.`,
	Args: cobra.ExactArgs(2),
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

		// Get vulnerability stats
		vulnStats, vulnErr := client.GetVulnerabilityStats(orgID, projectID, analysisID, summaryWorkspace)

		// Get SBOM stats
		sbomStats, sbomErr := client.GetSBOMStats(orgID, projectID, analysisID, summaryWorkspace)

		format, _ := cmd.Root().Flags().GetString("output")
		if format == "json" || format == "yaml" {
			// Output as structured data
			summary := map[string]interface{}{}
			if vulnErr == nil && vulnStats != nil {
				summary["vulnerabilities"] = vulnStats
			}
			if sbomErr == nil && sbomStats != nil {
				summary["dependencies"] = sbomStats
			}

			formatter := output.NewFormatter(format)
			return formatter.Print(summary)
		}

		// Table output
		fmt.Println(output.Bold("Analysis Summary"))
		fmt.Println()

		// Vulnerabilities
		fmt.Println(output.Bold("Vulnerabilities:"))
		if vulnErr != nil {
			output.Warning("  Could not retrieve vulnerability stats: %v", vulnErr)
		} else if vulnStats != nil {
			fmt.Printf("  Total:    %d\n", vulnStats.Total)
			fmt.Printf("  Critical: %s\n", output.SeverityColor(fmt.Sprintf("%d", vulnStats.Critical)))
			fmt.Printf("  High:     %s\n", output.SeverityColor(fmt.Sprintf("%d high", vulnStats.High)))
			fmt.Printf("  Medium:   %d\n", vulnStats.Medium)
			fmt.Printf("  Low:      %d\n", vulnStats.Low)
		}
		fmt.Println()

		// Dependencies
		fmt.Println(output.Bold("Dependencies:"))
		if sbomErr != nil {
			output.Warning("  Could not retrieve SBOM stats: %v", sbomErr)
		} else if sbomStats != nil {
			fmt.Printf("  Total:      %d\n", sbomStats.TotalDependencies)
			fmt.Printf("  Direct:     %d\n", sbomStats.DirectDependencies)
			fmt.Printf("  Transitive: %d\n", sbomStats.TransitiveDependencies)
		}

		return nil
	},
}

func init() {
	summaryCmd.Flags().StringVar(&summaryWorkspace, "workspace", "", "Filter by workspace")
}
