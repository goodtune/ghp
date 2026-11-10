//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProbeGHPCLI(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := script("ghp-ok", `[ "$1 $2 $3" = "auth git-credential --help" ] && exit 0; exit 3`)
	old := script("ghp-old", `echo 'unknown command "git-credential"' >&2; exit 1`)
	for _, tt := range []struct {
		name, path string
		want       bool
	}{
		{"helper present", ok, true},
		{"older ghp without the helper", old, false},
		{"missing binary", filepath.Join(dir, "nope"), false},
		{"unset", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := probeGHPCLI(context.Background(), tt.path); got != tt.want {
				t.Errorf("probeGHPCLI(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
