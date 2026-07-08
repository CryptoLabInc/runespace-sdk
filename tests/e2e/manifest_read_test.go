//go:build e2e

// manifest_read_test.go (D5): tombstone-marker GC, observed in the manifest via a
// shallow read-only SQLite read (pure-Go modernc driver, no cgo). A marker is purged
// once its id leaves EVERY live cell; the flat ACTIVE memtable keeps a non-rotated
// remainder by design (flat.CellRows includes the active cell — the documented
// flat-as-is window), so the global count drops substantially after an all-dead drop
// but not necessarily to 0. This asserts that substantial drop (the GC actually runs),
// rather than the unreachable ==0.
package e2e

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// tombstoned returns the count of tombstoned manifest entries, or -1 if the manifest
// can't be read right now (safe in a poll predicate; read-only with a busy timeout).
func (s *serverInst) tombstoned() int {
	db, err := sql.Open("sqlite", "file:"+s.manifestPath()+"?mode=ro&_pragma=busy_timeout(3000)")
	if err != nil {
		return -1
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM entries WHERE tombstoned = 1").Scan(&n); err != nil {
		return -1
	}
	return n
}

// TestHarness_TombstoneGC (D5): after an all-dead drop, the markers for ids that left
// every cell are purged (PurgeTombstoned). The count drops from ~n to the flat active
// remainder — substantial GC, observed directly in the manifest.
func TestHarness_TombstoneGC(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 16, stageThreshold: 256})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	n := rebalN()
	ids, _ := insertNearCentroid(t, s, c, 0, n, 23)
	s.waitFor(t, "cluster cell built", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, id := range ids {
		if err := c.Delete(ctx, id); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}

	// The deletes are durable immediately (SQLite tombstones; peak ≈ n), before any pass.
	s.waitFor(t, "manifest to reflect the deletes", 3*time.Minute, func() bool { return s.tombstoned() >= n-50 })
	peak := s.tombstoned()

	// Delete does not wake the rebalancer; the boot wake after a reboot runs the pass that
	// drops the all-dead cell, reclaims its now-covered staged flat cells…
	s.restart()
	s.waitReady(10 * time.Minute)
	s.waitFor(t, "all-dead cell dropped + staged flat reclaimed", 10*time.Minute,
		func() bool { return s.pvClusterCells() == 0 && s.pvStagedFlat() == 0 })

	// …so markers for ids now in NO cell are GC'd. Only the flat active remainder stays,
	// so the count drops well below n (substantial GC), not necessarily to 0.
	s.waitFor(t, "tombstone markers GC'd (drop below n/2)", 5*time.Minute,
		func() bool { tc := s.tombstoned(); return tc >= 0 && tc < n/2 })
	final := s.tombstoned()
	t.Logf("tombstone GC: peak=%d → %d (purged %d; the %d flat active-cell remainder persists by design)",
		peak, final, peak-final, final)
}
