// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"fmt"
	"math"
	"time"
)

// MaxTCPUserTimeout is the largest positive millisecond value accepted by
// Linux's TCP_USER_TIMEOUT socket option (a signed int).
const MaxTCPUserTimeout = time.Duration(math.MaxInt32) * time.Millisecond

// ValidateTCPUserTimeout rejects durations that cannot be represented by the
// socket option, rather than rounding a positive sub-millisecond value to zero.
func ValidateTCPUserTimeout(timeout time.Duration) error {
	if timeout < 0 || timeout > MaxTCPUserTimeout || timeout%time.Millisecond != 0 {
		return fmt.Errorf("TCP user timeout must be a whole number of milliseconds between 0 and %dms", MaxTCPUserTimeout.Milliseconds())
	}
	return nil
}
