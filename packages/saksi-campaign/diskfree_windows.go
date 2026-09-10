package campaign

import "golang.org/x/sys/windows"

// freeSpaceOn reports the bytes available to the calling user on the volume
// holding path (GetDiskFreeSpaceEx's first out-parameter, which already
// accounts for any quota on the account).
func freeSpaceOn(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}
