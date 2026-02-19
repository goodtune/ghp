package auth

import "fmt"

// AppInfo holds the OAuth credentials for a GitHub App.
// In single-app mode there is exactly one entry with an empty slug.
// In multi-app (vault) mode each entry has a distinct slug.
type AppInfo struct {
	Slug           string // unique identifier (vault key name); empty for legacy single-app
	AppID          int64
	ClientID       string
	ClientSecret   string
	PrivateKey     string // PEM-encoded (optional)
	EnterpriseSlug string // optional GitHub Enterprise Cloud slug
	DisplayName    string // human-friendly name shown in UI
}

// AppRegistry provides lookup of GitHub App credentials.
type AppRegistry struct {
	apps    map[string]*AppInfo // slug -> AppInfo
	slugs   []string            // ordered list of slugs
	multi   bool                // true when vault-backed multi-app mode
}

// NewSingleAppRegistry creates a registry with a single legacy app (no slug).
func NewSingleAppRegistry(app *AppInfo) *AppRegistry {
	app.Slug = ""
	if app.DisplayName == "" {
		app.DisplayName = "GitHub"
	}
	return &AppRegistry{
		apps:  map[string]*AppInfo{"": app},
		slugs: []string{""},
		multi: false,
	}
}

// NewMultiAppRegistry creates a registry with multiple apps keyed by slug.
func NewMultiAppRegistry(apps []*AppInfo) (*AppRegistry, error) {
	if len(apps) == 0 {
		return nil, fmt.Errorf("at least one app is required")
	}
	r := &AppRegistry{
		apps:  make(map[string]*AppInfo, len(apps)),
		multi: true,
	}
	for _, a := range apps {
		if a.Slug == "" {
			return nil, fmt.Errorf("app slug must not be empty in multi-app mode")
		}
		if _, exists := r.apps[a.Slug]; exists {
			return nil, fmt.Errorf("duplicate app slug: %s", a.Slug)
		}
		r.apps[a.Slug] = a
		r.slugs = append(r.slugs, a.Slug)
	}
	return r, nil
}

// Get returns the app for the given slug. In single-app mode the slug is ignored.
func (r *AppRegistry) Get(slug string) (*AppInfo, bool) {
	if !r.multi {
		a, ok := r.apps[""]
		return a, ok
	}
	a, ok := r.apps[slug]
	return a, ok
}

// Default returns the default (or only) app. In single-app mode this is the
// only app. In multi-app mode this returns the first registered app.
func (r *AppRegistry) Default() *AppInfo {
	if len(r.slugs) == 0 {
		return nil
	}
	return r.apps[r.slugs[0]]
}

// List returns all registered apps in order.
func (r *AppRegistry) List() []*AppInfo {
	out := make([]*AppInfo, 0, len(r.slugs))
	for _, s := range r.slugs {
		out = append(out, r.apps[s])
	}
	return out
}

// IsMultiApp returns true when multiple GitHub Apps are available.
func (r *AppRegistry) IsMultiApp() bool {
	return r.multi
}
