// SPDX-License-Identifier: Apache-2.0

package limiter

import "testing"

func TestGCRA(t *testing.T) {
	for _, c := range []struct{ rate, burst, shards, interval, tolerance uint64 }{
		// disabled
		{0, 100, 1, 0, 0},
		// 1ms per packet, 2000 deep
		{1000, 2000, 1, 1_000_000, 2_000_000_000},
		// burst floor is 1
		{1000, 0, 1, 1_000_000, 1_000_000},
		// 8 CPUs: 125k pps and 1000 burst each
		{1_000_000, 8000, 8, 8000, 8_000_000},
		// faster than 1/ns clamps, never disables
		{2e9, 10, 1, 1, 10},
	} {
		i, tol := GCRA(c.rate, c.burst, int(c.shards))
		if i != c.interval || tol != c.tolerance {
			t.Errorf("GCRA(%d,%d,%d) = %d,%d want %d,%d",
				c.rate, c.burst, c.shards, i, tol, c.interval, c.tolerance)
		}
	}
}
