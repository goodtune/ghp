package auth

import (
	"testing"
)

func TestNewSingleAppRegistry_DoesNotMutateCaller(t *testing.T) {
	app := &AppInfo{
		Slug:         "original-slug",
		AppID:        1,
		ClientID:     "cid",
		ClientSecret: "csec",
		DisplayName:  "My App",
	}
	_ = NewSingleAppRegistry(app)

	// The caller's AppInfo should not have been mutated.
	if app.Slug != "original-slug" {
		t.Errorf("caller's Slug was mutated to %q, want %q", app.Slug, "original-slug")
	}
}

func TestAppRegistry_GetReturnsCopy(t *testing.T) {
	app := &AppInfo{AppID: 1, ClientID: "cid", ClientSecret: "csec"}
	reg := NewSingleAppRegistry(app)

	got, ok := reg.Get("")
	if !ok {
		t.Fatal("Get returned false")
	}
	got.ClientID = "MUTATED"

	got2, _ := reg.Get("")
	if got2.ClientID == "MUTATED" {
		t.Error("Get returned a reference to internal state; mutation leaked")
	}
}

func TestAppRegistry_DefaultReturnsCopy(t *testing.T) {
	app := &AppInfo{AppID: 1, ClientID: "cid", ClientSecret: "csec"}
	reg := NewSingleAppRegistry(app)

	d := reg.Default()
	d.ClientID = "MUTATED"

	d2 := reg.Default()
	if d2.ClientID == "MUTATED" {
		t.Error("Default returned a reference to internal state; mutation leaked")
	}
}

func TestAppRegistry_ListReturnsCopies(t *testing.T) {
	app := &AppInfo{AppID: 1, ClientID: "cid", ClientSecret: "csec"}
	reg := NewSingleAppRegistry(app)

	list := reg.List()
	list[0].ClientID = "MUTATED"

	list2 := reg.List()
	if list2[0].ClientID == "MUTATED" {
		t.Error("List returned references to internal state; mutation leaked")
	}
}

func TestNewMultiAppRegistry_Validation(t *testing.T) {
	tests := []struct {
		name    string
		apps    []*AppInfo
		wantErr string
	}{
		{
			name:    "empty list",
			apps:    []*AppInfo{},
			wantErr: "at least one app",
		},
		{
			name: "empty slug",
			apps: []*AppInfo{
				{Slug: "", AppID: 1, ClientID: "c", ClientSecret: "s"},
			},
			wantErr: "slug must not be empty",
		},
		{
			name: "duplicate slug",
			apps: []*AppInfo{
				{Slug: "dup", AppID: 1, ClientID: "c1", ClientSecret: "s1"},
				{Slug: "dup", AppID: 2, ClientID: "c2", ClientSecret: "s2"},
			},
			wantErr: "duplicate app slug",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewMultiAppRegistry(tc.apps)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !containsSubstring(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestAppRegistry_MultiAppGet(t *testing.T) {
	apps := []*AppInfo{
		{Slug: "app-a", AppID: 1, ClientID: "ca", ClientSecret: "sa"},
		{Slug: "app-b", AppID: 2, ClientID: "cb", ClientSecret: "sb"},
	}
	reg, err := NewMultiAppRegistry(apps)
	if err != nil {
		t.Fatal(err)
	}

	got, ok := reg.Get("app-b")
	if !ok {
		t.Fatal("Get(app-b) returned false")
	}
	if got.AppID != 2 {
		t.Errorf("AppID = %d, want 2", got.AppID)
	}

	_, ok = reg.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) should return false")
	}
}

func TestAppRegistry_SingleAppGetIgnoresSlug(t *testing.T) {
	app := &AppInfo{AppID: 1, ClientID: "cid", ClientSecret: "csec"}
	reg := NewSingleAppRegistry(app)

	got, ok := reg.Get("any-slug")
	if !ok {
		t.Fatal("Get should return true for single-app regardless of slug")
	}
	if got.AppID != 1 {
		t.Errorf("AppID = %d, want 1", got.AppID)
	}
}

func TestAppRegistry_IsMultiApp(t *testing.T) {
	single := NewSingleAppRegistry(&AppInfo{AppID: 1, ClientID: "c", ClientSecret: "s"})
	if single.IsMultiApp() {
		t.Error("single app registry should not be multi-app")
	}

	multi, err := NewMultiAppRegistry([]*AppInfo{
		{Slug: "a", AppID: 1, ClientID: "ca", ClientSecret: "sa"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !multi.IsMultiApp() {
		t.Error("multi app registry should be multi-app")
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
