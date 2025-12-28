package cmd

import (
	"fmt"
	"os"

	"codeclarity.io/cli/cmd/analysis"
	"codeclarity.io/cli/cmd/analyzer"
	"codeclarity.io/cli/cmd/project"
	"codeclarity.io/cli/cmd/result"
	"codeclarity.io/cli/internal/config"
	"github.com/spf13/cobra"
)

var (
	// Version is set at build time
	Version = "dev"

	// Global flags
	orgID        string
	outputFormat string
	debug        bool
	apiURL       string

	// Config
	cfg *config.Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "codeclarity",
	Short: "CodeClarity CLI - Security analysis for your projects",
	Long: `CodeClarity CLI provides command-line access to the CodeClarity
security analysis platform. Analyze your projects for vulnerabilities,
license compliance, and generate software bill of materials.

Get started:
  codeclarity login              # Authenticate with your account
  codeclarity project list       # List your projects
  codeclarity analysis start     # Start a new analysis`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip config loading for certain commands
		if cmd.Name() == "login" || cmd.Name() == "version" || cmd.Name() == "help" {
			return nil
		}

		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Override with flags
		if apiURL != "" {
			cfg.APIBaseURL = apiURL
		}
		if outputFormat != "" {
			cfg.OutputFormat = outputFormat
		}
		if debug {
			cfg.Debug = true
		}

		return nil
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&orgID, "org", "o", "", "Organization ID (overrides default)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "f", "", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "API base URL (overrides config)")

	// Add subcommands
	rootCmd.AddCommand(analyzer.AnalyzerCmd)
	rootCmd.AddCommand(project.ProjectCmd)
	rootCmd.AddCommand(analysis.AnalysisCmd)
	rootCmd.AddCommand(result.ResultCmd)
}

// GetOrgID returns the organization ID from flags or config
func GetOrgID() string {
	if orgID != "" {
		return orgID
	}
	if cfg != nil && cfg.DefaultOrgID != "" {
		return cfg.DefaultOrgID
	}
	return ""
}

// GetOutputFormat returns the output format
func GetOutputFormat() string {
	if outputFormat != "" {
		return outputFormat
	}
	if cfg != nil && cfg.OutputFormat != "" {
		return cfg.OutputFormat
	}
	return "table"
}

// GetConfig returns the loaded configuration
func GetConfig() *config.Config {
	return cfg
}
