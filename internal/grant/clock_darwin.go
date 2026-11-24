package grant

import (
	"time"

	"golang.org/x/sys/unix"
)

func timeSinceBoot() (time.Duration, error) {
	// Darwin's CLOCK_MONOTONIC_RAW uses mach_continuous_time.
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts)
	return time.Duration(ts.Nano()), err
}
