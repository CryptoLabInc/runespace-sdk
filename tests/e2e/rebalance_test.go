//go:build e2e

// rebalance_test.go (W4): exercises the background cluster-rebalance worker via the
// process harness. Inserts a burst routed to a single centroid (vectors crafted near
// it), then asserts — through on-disk PV file counts and live searches — that the
// worker builds an immutable cluster cell, the items stay findable across the swap,
// the singles SoT is preserved, and the now-covered flat cells are reclaimed. Heavy
// (real dim-sized FHE + a real MM-cell assembly); opt-in via RUNESPACE_BIN.
package e2e

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// rebalN is how many items to route to one centroid. It must be >= half a cell
// (dim/2) for the small-centroid packing to seal a cluster cell, and (for the
// reclaim assertion) <= dim so a single cell covers them all. Default 600 (dim
// 1024). Override with RUNESPACE_REBAL_N.
func rebalN() int {
	if s := os.Getenv("RUNESPACE_REBAL_N"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 600
}

// insertNearCentroid inserts n items whose vectors sit near centroid centroidID (so
// the client routes them all there), returning their ids and vectors in order.
func insertNearCentroid(t *testing.T, s *serverInst, c *runespace.Client, centroidID, n int, seed int64) ([]string, [][]float32) {
	t.Helper()
	base := s.centroidVec(t, centroidID)
	rng := rand.New(rand.NewSource(seed))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ids := make([]string, n)
	vecs := make([][]float32, n)
	for i := 0; i < n; i++ {
		vecs[i] = nearCentroid(base, rng, 0.01)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"i":%d}`, i))
		if err != nil {
			t.Fatalf("insert %d near c%d: %v", i, centroidID, err)
		}
		ids[i] = id
	}
	return ids, vecs
}

// TestHarness_RebalanceBuildsAndReclaims drives one full rebalance pass: a burst
// routed to c0 accumulates as singles, the worker seals a cluster cell, every id
// stays findable, the singles persist, and the covered flat cells are dropped.
func TestHarness_RebalanceBuildsAndReclaims(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 128})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	n := rebalN()
	ids, vecs := insertNearCentroid(t, s, c, 0, n, 1)
	t.Logf("after %d inserts near c0: singles=%d stagedFlat=%d clusterCells=%d",
		n, s.pvSingles(), s.pvStagedFlat(), s.pvClusterCells())

	// The worker assembles an immutable cluster cell from the accumulated singles.
	s.waitFor(t, "a cluster cell to be built", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })

	// Every inserted id stays findable across the build/swap (>=1 coverage).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, i := range []int{0, n / 2, n - 1} {
		hits, err := c.Search(ctx, vecs[i], 10)
		if err != nil {
			t.Fatalf("search %d: %v", i, err)
		}
		if !containsID(hits, ids[i]) {
			t.Errorf("id %s (insert %d) missing after rebalance: %s", ids[i], i, summarizeHits(hits))
		}
	}

	// The singles remain the source of truth.
	if got := s.pvSingles(); got < n {
		t.Errorf("singles=%d after rebalance; want >= %d (SoT preserved)", got, n)
	}
	// The flat cells the cluster now fully covers are reclaimed (n <= dim ⇒ one
	// cluster cell covers every staged flat cell, so the staged backlog drains).
	s.waitFor(t, "covered flat cells to be reclaimed", 5*time.Minute, func() bool { return s.pvStagedFlat() == 0 })
	t.Logf("converged: clusterCells=%d stagedFlat=%d singles=%d", s.pvClusterCells(), s.pvStagedFlat(), s.pvSingles())
}

// insertScattered inserts n items with independent random (near-orthogonal in high
// dim) vectors, so each routes to its own centroid — the input for the many-to-one
// packing path. Returns ids and vectors in order.
func insertScattered(t *testing.T, c *runespace.Client, n, dim int, seed int64) ([]string, [][]float32) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ids := make([]string, n)
	vecs := make([][]float32, n)
	for i := range ids {
		vecs[i] = genVec(dim, rng)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"i":%d}`, i))
		if err != nil {
			t.Fatalf("scattered insert %d: %v", i, err)
		}
		ids[i] = id
	}
	return ids, vecs
}

// e7N is the one-to-many burst size; it must exceed 2*dim so a single centroid needs
// at least two full cells. Default 2100 (dim 1024); override with RUNESPACE_E7_N.
func e7N() int {
	if s := os.Getenv("RUNESPACE_E7_N"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 2100
}

// TestHarness_RebalanceManyToOnePacking (E5): a scattered burst — each item its own
// near-unique centroid — is whole-centroid bin-packed into a shared cluster cell, not
// one cell per centroid. Asserts a cell is sealed, with far fewer cells than items
// (many-to-one), and the (well-separated) items stay findable.
func TestHarness_RebalanceManyToOnePacking(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 16, stageThreshold: 256})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	const n = 600
	ids, vecs := insertScattered(t, c, n, s.dim, 20)
	s.waitFor(t, "packing to seal a shared cluster cell", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })
	cells := s.pvClusterCells()
	t.Logf("many-to-one: %d scattered items → %d cluster cell(s)", n, cells)
	if cells > n/4 {
		t.Errorf("cluster cells=%d for %d scattered items; want many-to-one packing (far fewer)", cells, n)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, i := range []int{0, n / 2, n - 1} {
		hits, err := c.Search(ctx, vecs[i], 20)
		if err != nil {
			t.Fatalf("search %d: %v", i, err)
		}
		if !containsID(hits, ids[i]) {
			t.Errorf("scattered id %s (item %d) missing after packing: %s", ids[i], i, summarizeHits(hits))
		}
	}
}

// TestHarness_RebalanceAllDeadDrop (E6): deleting every row of an assembled cluster cell
// leaves it masked (delete no longer wakes the worker — reclaim is opportunistic); a
// reboot's boot wake runs the pass that drops the now-all-dead cell (merge/retire path),
// purges its singles, and nothing resurfaces.
func TestHarness_RebalanceAllDeadDrop(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 16, stageThreshold: 256})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	n := rebalN()
	ids, vecs := insertNearCentroid(t, s, c, 0, n, 21)
	s.waitFor(t, "cluster cell built", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, id := range ids {
		if err := c.Delete(ctx, id); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}
	// Delete does not wake the rebalancer; the boot wake after a reboot runs the pass that
	// drops the now-all-dead cell and purges its singles.
	s.restart()
	s.waitReady(10 * time.Minute)
	s.waitFor(t, "all-dead cluster cell to be dropped", 10*time.Minute, func() bool { return s.pvClusterCells() == 0 })
	t.Logf("all-dead drop: %d deleted → clusterCells=%d stagedFlat=%d singles=%d",
		n, s.pvClusterCells(), s.pvStagedFlat(), s.pvSingles())

	c = s.client(t)
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer scancel()
	hits, err := c.Search(sctx, vecs[0], 20)
	if err != nil {
		t.Fatalf("post-drop search: %v", err)
	}
	for _, id := range ids {
		if containsID(hits, id) {
			t.Errorf("deleted id %s still present after all-dead drop: %s", id, summarizeHits(hits))
			break
		}
	}
}

// TestHarness_RebalanceOneToMany (E7): a single centroid past one cell's capacity
// (>2*dim items) spreads across multiple immutable cells (append-only big path) — a
// centroid mapping to many cells. Asserts >=2 cluster cells and a live cluster hit.
// Heavy (>2*dim real encryptions); RUNESPACE_E7_N tunes the count.
func TestHarness_RebalanceOneToMany(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 16, stageThreshold: 512})
	s.start()
	s.register()
	s.waitReady(15 * time.Minute)

	c := s.client(t)
	n := e7N()
	_, vecs := insertNearCentroid(t, s, c, 0, n, 22)
	s.waitFor(t, "one centroid to span >=2 cluster cells", 15*time.Minute, func() bool { return s.pvClusterCells() >= 2 })
	t.Logf("one-to-many: %d near c0 → %d cluster cells", n, s.pvClusterCells())

	// The items are mutually near-identical, so assert the cluster tier is live/probed
	// (a cluster-tier hit) rather than a specific id's rank.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	hits, err := c.Search(ctx, vecs[0], 100)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	clusterHit := false
	for _, h := range hits {
		if h.ClusterID != runespace.FlatClusterID {
			clusterHit = true
			break
		}
	}
	if !clusterHit {
		t.Errorf("no cluster-tier hit after one-to-many split: %s", summarizeHits(hits))
	}
}

// reclaimN is the burst for the big-cell reclaim test: it must exceed 3*dim so one
// centroid spans >=3 full append-only cells, leaving room to hollow every cell below the
// reassemble fraction while the surviving rows still exceed dim — so the centroid stays
// big and the reclaim (not the small re-derive) path runs. Default 3100 (dim 1024);
// override with RUNESPACE_RECLAIM_N.
func reclaimN() int {
	if s := os.Getenv("RUNESPACE_RECLAIM_N"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 3100
}

// TestHarness_RebalanceReclaimHollowBig (E6, big-stays-big): a big centroid spans >=3
// append-only cells; deleting ~60% of the rows (strided, so every cell loses ~60%
// regardless of its membership) hollows each cell below reassemble_live_fraction=0.5
// while the centroid stays big (survivors > dim). A reboot's boot wake re-packs the
// hollow cells into strictly fewer (⌈survivors/dim⌉ < cells) — freeing a block — and no
// deleted id resurfaces. Heavy (>3*dim real encryptions); RUNESPACE_RECLAIM_N tunes it.
func TestHarness_RebalanceReclaimHollowBig(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 16, stageThreshold: 512, reassembleLiveFraction: 0.5})
	s.start()
	s.register()
	s.waitReady(15 * time.Minute)

	c := s.client(t)
	n := reclaimN()
	ids, vecs := insertNearCentroid(t, s, c, 0, n, 24)
	s.waitFor(t, "one centroid to span >=3 cluster cells", 15*time.Minute, func() bool { return s.pvClusterCells() >= 3 })
	cells0 := s.pvClusterCells()
	t.Logf("big centroid: %d near c0 → %d cluster cells", n, cells0)

	// Hollow every cell: delete 3 of every 5 ids. Cell membership is a partition of the
	// ids, so any cell loses ~60% (leaving ~40% live, below 0.5); the survivors still
	// exceed dim, so the centroid stays big and the reclaim path (not the re-derive) runs.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	deleted := make(map[string]bool, n)
	var survivor int = -1
	for i, id := range ids {
		if i%5 < 3 {
			if err := c.Delete(ctx, id); err != nil {
				t.Fatalf("delete %s: %v", id, err)
			}
			deleted[id] = true
		} else if survivor < 0 {
			survivor = i
		}
	}
	t.Logf("hollowed: deleted %d/%d", len(deleted), n)

	// Delete does not wake the rebalancer; the boot wake after a reboot runs the reclaim
	// pass that merges the hollow cells into strictly fewer (a freed block).
	s.restart()
	s.waitReady(15 * time.Minute)
	s.waitFor(t, "hollow big cells to re-pack into fewer", 15*time.Minute, func() bool {
		cn := s.pvClusterCells()
		return cn >= 1 && cn < cells0
	})
	cellsN := s.pvClusterCells()
	t.Logf("reclaim: %d → %d cluster cells (freed %d block(s))", cells0, cellsN, cells0-cellsN)

	// The cluster still serves the survivors and no deleted id resurfaces.
	c = s.client(t)
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer scancel()
	hits, err := c.Search(sctx, vecs[survivor], 100)
	if err != nil {
		t.Fatalf("post-reclaim search: %v", err)
	}
	clusterHit := false
	for _, h := range hits {
		if h.ClusterID != runespace.FlatClusterID {
			clusterHit = true
		}
		if deleted[h.ID] {
			t.Errorf("deleted id %s resurfaced after reclaim: %s", h.ID, summarizeHits(hits))
			break
		}
	}
	if !clusterHit {
		t.Errorf("no cluster-tier hit after reclaim: %s", summarizeHits(hits))
	}
}
