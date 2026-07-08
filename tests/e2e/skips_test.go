//go:build e2e

// skips_test.go: scenarios from the QA plan that are NOT cleanly e2e-testable against
// a real server without production-code failpoints, an old client build, or a way to
// force a minutes-long blind search. They are recorded as explicit skips (with the
// reason) so the gap is visible in `go test -v` output — a known, reasoned omission
// rather than a silent one.
//
// Scenarios whose intent is already covered by a real green test are NOT kept here as
// empty placeholders — they were removed once verified covered:
//   - A7 (register mid-stream disconnect) → A5 (incomplete stream applies nothing) +
//     A8 (crash mid-register reboots consistently).
//   - B3 (insertWithRetry on UNAVAILABLE) → TestE2E_InsertIdempotent (same id resolves
//     exactly once); the retry loop itself is an SDK unit concern, not e2e.
//   - B8 (ctx-cancel finishes the manifest write) → TestHarness_CrashMidInsertRecovers
//     (boot reconcileOrphans — the no-orphan invariant it protects).
//
// What remains below is genuinely uncovered, not redundant.
package e2e

import "testing"

// G2: rebalance wake coalescing (one wake per staged cell, not per insert).
func TestE2E_Skip_WakeCoalescing(t *testing.T) {
	t.Skip("G2: the worker's wake count is not exposed externally (no metric/RPC). The " +
		"staged-cell trigger model is exercised by the rebalance tests, but asserting the " +
		"coalescing COUNT (which those tests would still pass without) needs an internal probe.")
}

// H4: a minutes-long quiet blind search survives the keepalive floor (no GOAWAY).
func TestE2E_Skip_KeepaliveLongQuietSearch(t *testing.T) {
	t.Skip("H4: cannot force a minutes-long quiet search deterministically under R9 (searches " +
		"are fast; lazy per-cluster assembly was removed). The keepalive floor is set in " +
		"serve.go (minClientPingInterval) and verified by manual long-run observation.")
}

// I2: an OLD SDK build against the NEW server (version skew / Unimplemented fallback).
func TestE2E_Skip_VersionSkew(t *testing.T) {
	t.Skip("I2: needs an older SDK build pinned to a prior proto, which a single working tree " +
		"can't provide. This is a manual cross-version check at release time.")
}
