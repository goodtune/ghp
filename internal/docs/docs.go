// Package docs provides the embedded documentation site for ghp.
package docs

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:site
var siteFS embed.FS

// Handler returns an http.Handler that serves the embedded documentation
// site built by mkdocs.
func Handler() http.Handler {
	sub, _ := fs.Sub(siteFS, "site")
	return http.FileServerFS(sub)
}
