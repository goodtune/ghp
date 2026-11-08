package main

import "testing"

// setTestHome points the user's home directory at dir for the duration of
// the test. os.UserHomeDir reads HOME on Unix and USERPROFILE on Windows, so
// both are set; setting USERPROFILE on Unix is harmless.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}
