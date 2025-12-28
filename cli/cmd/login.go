package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"codeclarity.io/cli/internal/api"
	"codeclarity.io/cli/internal/auth"
	"codeclarity.io/cli/internal/config"
	"codeclarity.io/cli/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	loginEmail    string
	loginPassword string
)

var loginAPIURL string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with CodeClarity",
	Long: `Authenticate with your CodeClarity account and store tokens locally.

The credentials are stored securely in ~/.codeclarity/credentials.yaml
with restricted file permissions.

You can specify a custom API URL with --api-url:
  codeclarity login --api-url https://your-instance.example.com/api

For CI/CD environments, you can use the CODECLARITY_API_KEY environment
variable instead of interactive login.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load config for API URL
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Override API URL if provided (local flag takes precedence over global)
		customAPIURL := loginAPIURL
		if customAPIURL == "" && apiURL != "" {
			customAPIURL = apiURL
		}
		if customAPIURL != "" {
			cfg.APIBaseURL = customAPIURL
		}

		// Get email
		email := loginEmail
		if email == "" {
			fmt.Print("Email: ")
			reader := bufio.NewReader(os.Stdin)
			email, _ = reader.ReadString('\n')
			email = strings.TrimSpace(email)
		}

		// Get password
		password := loginPassword
		if password == "" {
			fmt.Print("Password: ")
			bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			password = string(bytePassword)
			fmt.Println()
		}

		// Authenticate
		client := api.NewClient(cfg.APIBaseURL)
		resp, err := client.Authenticate(email, password)
		if err != nil {
			output.Error("Authentication failed: %v", err)
			return nil
		}

		// Get user info
		client.SetToken(resp.Token)
		user, err := client.GetCurrentUser()
		if err != nil {
			output.Error("Failed to get user info: %v", err)
			return nil
		}

		// Store tokens
		tokens := &auth.TokenStore{
			AccessToken:        resp.Token,
			RefreshToken:       resp.RefreshToken,
			TokenExpiry:        resp.TokenExpiry,
			RefreshTokenExpiry: resp.RefreshTokenExpiry,
			UserID:             user.ID,
			Email:              user.Email,
		}

		if err := auth.SaveTokens(tokens); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}

		// Update config with default org and API URL
		defaultOrgID := user.GetDefaultOrgID()
		configChanged := false

		if defaultOrgID != "" {
			cfg.DefaultOrgID = defaultOrgID
			configChanged = true
		}

		if customAPIURL != "" {
			cfg.APIBaseURL = customAPIURL
			configChanged = true
		}

		if configChanged {
			if err := config.Save(cfg); err != nil {
				output.Warning("Failed to save configuration: %v", err)
			}
		}

		output.Success("Logged in as %s", user.Email)
		if customAPIURL != "" {
			output.Info("API URL: %s", cfg.APIBaseURL)
		}
		if defaultOrgID != "" {
			output.Info("Default organization: %s", defaultOrgID)
		}

		return nil
	},
}

func init() {
	loginCmd.Flags().StringVarP(&loginEmail, "email", "e", "", "Account email")
	loginCmd.Flags().StringVarP(&loginPassword, "password", "p", "", "Account password (not recommended, use interactive prompt)")
	loginCmd.Flags().StringVar(&loginAPIURL, "api-url", "", "API base URL (e.g., https://your-instance.example.com/api)")
	rootCmd.AddCommand(loginCmd)
}
