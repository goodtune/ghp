package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	cobradoc "github.com/spf13/cobra/doc"
)

func newDocCmd(rootCmd *cobra.Command) *cobra.Command {
	var outputDir string

	cmd := &cobra.Command{
		Use:    "doc",
		Short:  "Generate man pages",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("creating output directory: %w", err)
			}
			header := &cobradoc.GenManHeader{
				Title:   "GHP",
				Section: "1",
				Source:  "ghp " + version,
			}
			return cobradoc.GenManTree(rootCmd, header, outputDir)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "doc/man1", "output directory for man pages")
	return cmd
}
