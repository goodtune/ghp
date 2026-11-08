// Package main is the entrypoint for the ghp CLI.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Set at build time via -ldflags.
var version = "dev"

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ghp",
		Short: "GitHub Proxy for Autonomous Coding Agents",
		Long:  "ghp is a GitHub API reverse proxy that issues scoped, auditable tokens to autonomous coding agents.",
	}

	rootCmd.PersistentFlags().String("config", "", "path to server configuration file (or set GHP_CONFIG)")

	rootCmd.AddCommand(
		newServeCmd(),
		newMigrateCmd(),
		newAuthCmd(),
		newTokenCmd(),
		newAppTokenCmd(),
		newWebhooksCmd(),
		newVersionCmd(),
		newDocCmd(rootCmd),
	)

	return rootCmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			// The command has already reported the failure itself.
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// exitCodeError makes main exit with code without printing anything: the
// command has already written its own diagnostics (the git credential
// helper must leave exactly one prefixed stderr line).
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "ghp version %s\n", version)
		},
	}
}
