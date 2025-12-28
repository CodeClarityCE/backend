package cmd

import (
	"codeclarity.io/cli/internal/auth"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored credentials",
	Long:  `Remove stored authentication tokens from ~/.codeclarity/credentials.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.ClearTokens(); err != nil {
			output.Error("Failed to clear credentials: %v", err)
			return nil
		}

		output.Success("Logged out successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
