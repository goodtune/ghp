//go:build !unix

package exec

import osexec "os/exec"

// setProcessGroup is a no-op where process groups are unavailable; the
// default cancel kills only the gh process itself.
func setProcessGroup(*osexec.Cmd) {}
