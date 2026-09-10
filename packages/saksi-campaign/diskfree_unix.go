//go:build !windows

package campaign

import "golang.org/x/sys/unix"

// freeSpaceOn reports the bytes available to an unprivileged writer on the
// filesystem holding path. Bavail, not Bfree: the reserved blocks a superuser
// could still use are not space this run may have.
func freeSpaceOn(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
