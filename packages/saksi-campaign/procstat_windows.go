//go:build windows

package campaign

import "syscall"

// processCPUSeconds returns this process's total (kernel+user) CPU time in
// seconds since start, via GetProcessTimes. Used by the sampler to derive a
// CPU% for the console's own "client" sample. Uses the stdlib syscall
// package rather than golang.org/x/sys/windows: x/sys is only an indirect
// dependency of this module today, and syscall already has everything
// needed here.
func processCPUSeconds() (float64, bool) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, false
	}
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, false
	}
	toSeconds := func(ft syscall.Filetime) float64 {
		// Filetime counts 100-nanosecond intervals.
		v := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
		return float64(v) / 1e7
	}
	return toSeconds(kernel) + toSeconds(user), true
}
