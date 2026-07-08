//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// TestE2E_ClusteredCompactionDeleteTombstone exercises the delete-AFTER-compaction
// path the assemble/merge test does not: it deletes an id that is already BAKED INTO
// an assembled cluster cell and checks the tombstone still folds it out.
//
// Flow: insert dual-rep items, then run a clustered search to force the lazy
// per-cluster MM assembly (the "compaction") — the probe item is now physically a
// row in its cluster's immutable cell. A subsequent Delete writes only a manifest
// tombstone; it does NOT re-assemble the cell, so the deleted row still lives inside
// it. The only thing that can keep that row out of the next clustered search is the
// server's query-time dead-row filter (the per-cluster tombstone fold). The test
// asserts the deleted id disappears from the merged result while a neighbour that was
// NOT deleted stays searchable through the same compacted cells — i.e. the tombstone
// is surgical and propagates through a tier compacted before the delete.
//
// Requires RUNESPACE_CLUSTERED=1 (instance has a centroid set matching RUNESPACE_DIM).
func TestE2E_ClusteredCompactionDeleteTombstone(t *testing.T) {
	ids, vecs := clusteredFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n := len(ids) // search the whole concentrated corpus so presence/absence is reliable
	c := e2eClient(t)

	// probe and survivor are items the shared fixture already assembled into their
	// cluster cells (and that the assemble-search test does not probe), so the delete
	// below genuinely exercises the per-cluster dead-row filter.
	const probe = 13
	const survivor = 14

	// (1) Confirm the MM tier is live and competitive before the delete. Per-probe
	// "did clusters win" is a coin-flip (see TestE2E_ClusteredInsertAssembleSearch),
	// so aggregate across several probes; also confirm the probe itself is present.
	wins := clusterWonAcross(t, c, ids, vecs, []int{probe, 5, 19, 27, 33, 40, 44, 51, 58, 2}, n, false)
	if wins == 0 {
		t.Fatal("no clustered hits across probes after assembly: compaction produced nothing competitive; the cluster tombstone path would go untested")
	}
	pre, err := c.Search(ctx, vecs[probe], n)
	if err != nil {
		t.Fatalf("pre-delete clustered Search: %v", err)
	}
	if !containsID(pre, ids[probe]) {
		t.Fatalf("probe id %s missing pre-delete: %s", ids[probe], summarizeHits(pre))
	}
	t.Logf("post-compaction: clusters competitive (won >=1 in %d probes); probe %s present", wins, ids[probe])

	// (2) Delete the probe. It is already a row inside an assembled cluster cell; the
	// Delete writes a manifest tombstone only and does not rebuild the cell.
	if err := c.Delete(ctx, ids[probe]); err != nil {
		t.Fatalf("Delete probe: %v", err)
	}

	// (3) Re-run the SAME clustered search. The cell was not rebuilt, so if the
	// query-time dead-row filter failed to fold the tombstone, the row would resurface
	// from the cluster tier at ~1.0. Assert it is gone from every tier.
	post, err := c.Search(ctx, vecs[probe], n)
	if err != nil {
		t.Fatalf("post-delete clustered Search: %v", err)
	}
	if containsID(post, ids[probe]) {
		t.Fatalf("deleted id %s still present after compaction+delete (cluster tombstone not folded): %s",
			ids[probe], summarizeHits(post))
	}
	t.Logf("tombstone folded: probe %s absent from %d post-delete hits", ids[probe], len(post))

	// (4) Surgical: a neighbour that was NOT deleted must still be found through the
	// same compacted cells, and the deleted id must not leak into a different query.
	shits, err := c.Search(ctx, vecs[survivor], n)
	if err != nil {
		t.Fatalf("survivor Search: %v", err)
	}
	if !containsID(shits, ids[survivor]) {
		t.Errorf("survivor id %s missing after deleting a different id (over-deletion?): %s",
			ids[survivor], summarizeHits(shits))
	}
	if containsID(shits, ids[probe]) {
		t.Errorf("deleted id %s leaked into a neighbour query: %s", ids[probe], summarizeHits(shits))
	}
	t.Logf("surgical: survivor %s still found across %d hits; deleted id stays gone", ids[survivor], len(shits))
}

func containsID(hits []runespace.Match, id string) bool {
	for _, h := range hits {
		if h.ID == id {
			return true
		}
	}
	return false
}

// summarizeHits renders hits compactly for failure messages (id/score/cluster).
func summarizeHits(hits []runespace.Match) string {
	s := fmt.Sprintf("%d hits:", len(hits))
	for i, h := range hits {
		if i >= 8 {
			s += " ..."
			break
		}
		s += fmt.Sprintf(" [%s s=%.3f c=%d]", h.ID, h.Score, h.ClusterID)
	}
	return s
}
