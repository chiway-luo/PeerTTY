package grant

import (
	"time"

	"golang.org/x/sys/unix"
)

func timeSinceBoot() (time.Duration, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return time.Duration(ts.Nano()), err
}
