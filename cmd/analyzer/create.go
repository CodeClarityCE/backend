package analyzer

import (
	"encoding/json"
	"fmt"
	"os"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/output"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	createFile        string
	createName        string
	createDescription string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new analyzer",
	Long: `Create a new analyzer configuration.

You can provide the analyzer configuration via a JSON or YAML file:
  codeclarity analyzer create --file analyzer.yaml

Or specify basic options:
  codeclarity analyzer create --name "My Analyzer" --description "..."`,
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

		var req api.AnalyzerCreateRequest

		if createFile != "" {
			// Load from file
			data, err := os.ReadFile(createFile)
			if err != nil {
				output.Error("Failed to read file: %v", err)
				return nil
			}

			// Try YAML first, then JSON
			if err := yaml.Unmarshal(data, &req); err != nil {
				if err := json.Unmarshal(data, &req); err != nil {
					output.Error("Failed to parse file: %v", err)
					return nil
				}
			}
		} else {
			// Use command line flags
			if createName == "" {
				output.Error("Name is required. Use --name or --file")
				return nil
			}
			if createDescription == "" {
				output.Error("Description is required. Use --description or --file")
				return nil
			}

			req = api.AnalyzerCreateRequest{
				Name:        createName,
				Description: createDescription,
				Steps:       [][]api.Stage{}, // Empty steps - user should use file for complex analyzers
			}
		}

		id, err := client.CreateAnalyzer(orgID, req)
		if err != nil {
			output.Error("Failed to create analyzer: %v", err)
			return nil
		}

		output.Success("Analyzer created: %s", id)
		fmt.Printf("ID: %s\n", id)

		return nil
	},
}

func init() {
	createCmd.Flags().StringVarP(&createFile, "file", "f", "", "Path to analyzer configuration file (JSON or YAML)")
	createCmd.Flags().StringVar(&createName, "name", "", "Analyzer name")
	createCmd.Flags().StringVar(&createDescription, "description", "", "Analyzer description")
}
