package vangoh

import (
	"time"
)

type Clock struct {
	Now func() time.Time
}

var clock = Clock{}

// Set up default implementations of all dependencies.
// Tests can override these implementations as necessary.
func init() {
	clock.Now = func() time.Time {
		return time.Now()
	}
}
