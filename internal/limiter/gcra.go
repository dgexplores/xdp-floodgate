// SPDX-License-Identifier: Apache-2.0

// Package limiter holds the rate-limit math shared by the loader and,
// later, the adaptive control loops.
package limiter

// GCRA converts a human limit (rate packets/sec, burst packets) into the
// two numbers the XDP program uses:
//
//	interval  = ns each packet "costs"          = 1e9 / rate
//	tolerance = how far ahead a sender may run  = burst * interval
//
// shards splits the limit across independent buckets (one per CPU for the
// node-wide cap): each shard gets rate/shards and burst/shards.
// rate == 0 returns (0, 0), which the XDP program treats as "no limit".
func GCRA(rate, burst uint64, shards int) (intervalNs, toleranceNs uint64) {
	if rate == 0 {
		return 0, 0
	}
	if shards < 1 {
		shards = 1
	}
	n := uint64(shards)
	intervalNs = 1e9 * n / rate
	if intervalNs == 0 { // > 1e9 pps per shard: clamp rather than disable
		intervalNs = 1
	}
	burst /= n
	if burst < 1 {
		burst = 1
	}
	return intervalNs, burst * intervalNs
}
