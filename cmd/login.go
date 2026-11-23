package cmd

import (
	"fmt"
	"os"

	"codeclarity.io/internal/api"
	"codeclarity.io/internal/session"
	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	var s session.Session
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in with an Organization token",
		Long: `Log in with an Organization token and store it in ~/.codeclarity/credentials.json (mode 0600).

The token comes from --token or CODECLARITY_TOKEN; prefer the variable, so the token stays out
of the process list and the shell history. --url and --org default to CODECLARITY_URL and
CODECLARITY_ORG. Instead of logging in, a pipeline can set all three variables.

  CODECLARITY_TOKEN=ccot_... codeclarity login --url https://codeclarity.example.com/api --org <organization id>`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fill(&s.URL, session.URLEnv)
			fill(&s.OrganizationID, session.OrgEnv)
			fill(&s.Token, session.TokenEnv)
			switch {
			case s.URL == "":
				return fmt.Errorf("no instance: pass --url or set %s", session.URLEnv)
			case s.OrganizationID == "":
				return fmt.Errorf("no organization: pass --org or set %s", session.OrgEnv)
			case s.Token == "":
				return fmt.Errorf("no Organization token: pass --token or set %s", session.TokenEnv)
			}
			if err := api.New(s.URL, s.Token).CheckAccess(cmd.Context(), s.OrganizationID); err != nil {
				return fmt.Errorf("the instance refused the token: %w", err)
			}
			if err := session.Save(s); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Logged in to organization %s on %s\n", s.OrganizationID, s.URL)
			return err
		},
	}
	cmd.Flags().StringVar(&s.URL, "url", "", "API URL of the instance, such as https://codeclarity.example.com/api")
	cmd.Flags().StringVar(&s.OrganizationID, "org", "", "id of the organization the token belongs to")
	cmd.Flags().StringVar(&s.Token, "token", "", "Organization token (prefer "+session.TokenEnv+")")
	return cmd
}

// fill sets an empty flag value from the environment.
func fill(value *string, env string) {
	if *value == "" {
		*value = os.Getenv(env)
	}
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Forget the stored Organization token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := session.Clear(); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Logged out")
			return err
		},
	}
}
