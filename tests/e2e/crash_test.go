//go:build e2e

// crash_test.go (W5): recovery + crash resilience via the process harness. Asserts
// WAL-before-ack durability (an acked write survives an abrupt SIGKILL), graceful
// restart, and that a crash MID-REBALANCE recovers with no lost ids — the boot wake
// replans from the durable singles + cell_map, so recovery is correct from ANY
// durable state (the saga boundary the kill lands on is intentionally nondeterministic).
// Opt-in via RUNESPACE_BIN.
package e2e

import (
	"context"
	"testing"
	"time"
)

// TestHarness_WALBeforeAck: acked inserts survive an immediate SIGKILL (RPO≈0).
func TestHarness_WALBeforeAck(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 128})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ids, vecs := insertNearCentroid(t, s, c, 0, 5, 2) // small, all acked
	s.kill()                                          // abrupt: no graceful drain
	s.start()
	s.waitReady(10 * time.Minute)

	c2 := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := range ids {
		hits, err := c2.Search(ctx, vecs[i], 10)
		if err != nil {
			t.Fatalf("post-crash search %d: %v", i, err)
		}
		if !containsID(hits, ids[i]) {
			t.Errorf("acked id %s lost across SIGKILL (RPO>0): %s", ids[i], summarizeHits(hits))
		}
	}
}

// TestHarness_GracefulRestartPreservesData: a SIGTERM drain + reboot keeps data.
func TestHarness_GracefulRestartPreservesData(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 128})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ids, vecs := insertNearCentroid(t, s, c, 0, 5, 3)
	s.term() // graceful drain within the grace window
	s.start()
	s.waitReady(10 * time.Minute)

	c2 := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := range ids {
		hits, err := c2.Search(ctx, vecs[i], 10)
		if err != nil {
			t.Fatalf("post-restart search %d: %v", i, err)
		}
		if !containsID(hits, ids[i]) {
			t.Errorf("id %s lost across graceful restart: %s", ids[i], summarizeHits(hits))
		}
	}
}

// TestHarness_CrashDuringRebalance: SIGKILL right after a rebalance-inducing burst
// (the worker is very likely mid-pass), then recover and require no lost ids and an
// intact singles SoT.
func TestHarness_CrashDuringRebalance(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 128})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	n := rebalN()
	ids, vecs := insertNearCentroid(t, s, c, 0, n, 4)
	s.kill() // crash at a nondeterministic point in the rebalance saga
	s.start()
	s.waitReady(10 * time.Minute)
	// The boot wake replans from the durable singles + cell_map; let it converge.
	s.waitFor(t, "post-crash rebalance to converge", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })

	c2 := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	missing := 0
	for i := range ids {
		hits, err := c2.Search(ctx, vecs[i], 10)
		if err != nil {
			t.Fatalf("post-crash search %d: %v", i, err)
		}
		if !containsID(hits, ids[i]) {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d/%d acked ids lost after a crash mid-rebalance", missing, len(ids))
	}
	if got := s.pvSingles(); got < n {
		t.Errorf("singles=%d after crash recovery; want >= %d (SoT must survive)", got, n)
	}
}
