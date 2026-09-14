package campaign

import "os/exec"

// killProcessGroup keeps exec's default cancel (kill the process). A reset is
// refused on Windows before anything runs, so there is no tree to take down.
func killProcessGroup(*exec.Cmd) {}
