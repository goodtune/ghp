//go:build !unix

package exec

import osexec "os/exec"

// SetProcessGroup is a no-op where process groups are unavailable; the
// default cancel kills only the gh process itself.
func SetProcessGroup(*osexec.Cmd) {}
