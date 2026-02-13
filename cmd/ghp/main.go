// Package main is the entrypoint for the ghp CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Set at build time via -ldflags.
var version = "dev"

func main() {
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
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ghp version %s\n", version)
		},
	}
}
