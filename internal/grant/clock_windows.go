package grant

import (
	"time"

	"golang.org/x/sys/windows"
)

func timeSinceBoot() (time.Duration, error) { return windows.DurationSinceBoot(), nil }
