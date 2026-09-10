//go:build linux || darwin

package campaign

import "syscall"

// processCPUSeconds returns this process's total (user+sys) CPU time in
// seconds since start, via getrusage(RUSAGE_SELF). Used by the sampler to
// derive a CPU% for the console's own "client" sample.
func processCPUSeconds() (float64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	user := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
	sys := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
	return user + sys, true
}
