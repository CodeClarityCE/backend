// Package cmd holds the CLI commands a CI pipeline runs: login, logout, version, analyze and results.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time.
var Version = "dev"

// exitError ends a run with a chosen exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }

func (e *exitError) Unwrap() error { return e.err }

// newRootCmd builds the command tree, writing to stdout and stderr.
func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "codeclarity",
		Short: "Analyse a project on a CodeClarity instance from a CI pipeline",
		Long: `Analyse a project on a CodeClarity instance from a CI pipeline.

  codeclarity login --url https://codeclarity.example.com/api --org <organization id>
  codeclarity analyze . --analyzer "Default Analyzer"
  codeclarity results --format json

Log in with an Organization token, from --token or CODECLARITY_TOKEN.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newVersionCmd(), newLoginCmd(), newLogoutCmd(), newAnalyzeCmd(), newResultsCmd())
	return root
}

// Run runs the CLI with args and returns its exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "Error:", err)
	var exit *exitError
	if errors.As(err, &exit) {
		return exit.code
	}
	return 1
}

// Execute runs the CLI with the process arguments and exits.
func Execute() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "codeclarity %s\n", Version)
			return err
		},
	}
}
