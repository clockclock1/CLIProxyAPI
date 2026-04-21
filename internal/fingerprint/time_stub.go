package fingerprint

import "time"

// nanoTime returns current time in nanoseconds for UUID entropy mixing.
func nanoTime() int64 {
	return time.Now().UnixNano()
}
