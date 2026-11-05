// Command importghdebug converts GH_DEBUG=api captures (<name>.txt) into
// corpus files (<name>.json). Existing expectations in the output directory
// are preserved per operation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/corpus"
	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/redact"
)

func main() {
	in := flag.String("in", "", "directory of GH_DEBUG=api captures (*.txt)")
	out := flag.String("out", "", "output corpus directory")
	version := flag.String("gh-version", "", "gh version the captures came from")
	owner := flag.String("owner", "", "real repository owner in the captures")
	repo := flag.String("repo", "", "real repository name in the captures")
	flag.Parse()
	if *in == "" || *out == "" || *version == "" || *owner == "" || *repo == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*in, *out, *version, *owner, *repo); err != nil {
		fmt.Fprintln(os.Stderr, "importghdebug:", err)
		os.Exit(1)
	}
}

func run(in, out, version, owner, repo string) error {
	names, err := filepath.Glob(filepath.Join(in, "*.txt"))
	if err != nil {
		return err
	}
	sort.Strings(names)
	type result struct {
		path string
		data []byte
	}
	var results []result
	for _, n := range names {
		capture := strings.TrimSuffix(filepath.Base(n), ".txt")
		command := corpus.CommandName(capture, owner, repo)
		fileBase := strings.ReplaceAll(command, " ", "_")
		ex, err := parseFile(n)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		dst := filepath.Join(out, fileBase+".json")
		prev, err := loadPrev(dst)
		if err != nil {
			return fmt.Errorf("%s: %w", dst, err)
		}
		f, err := corpus.Build(version, command, owner, repo, ex, prev)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		b, err := corpus.Marshal(f)
		if err != nil {
			return err
		}
		// Defence in depth: corpus.Marshal already refuses token-shaped output.
		if redact.Contains(b) {
			return fmt.Errorf("%s: token-shaped string in output; refusing to write", n)
		}
		results = append(results, result{dst, b})
	}
	// Write only after every file built cleanly.
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, r := range results {
		if err := os.WriteFile(r.path, r.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func parseFile(name string) ([]ghdebug.Exchange, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ghdebug.Parse(f)
}

func loadPrev(path string) (*corpus.File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f corpus.File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
