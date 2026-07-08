//go:build e2e

// concurrency_test.go (W6): a search running concurrently with a rebalance-inducing
// insert burst (>=1 coverage must hold throughout the blue-green swap), and a
// delete/search race (no error/leak, survivors stay). Run the whole suite under
// -race to catch data races in the client and on the wire.
package e2e

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHarness_SearchDuringRebalance: a probe id stays findable in every concurrent
// search while a burst drives the cluster swap (the blue-green ≥1 Coverage invariant).
func TestHarness_SearchDuringRebalance(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 128})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	seedIDs, seedVecs := insertNearCentroid(t, s, c, 0, 1, 10)
	probeID, probeVec := seedIDs[0], seedVecs[0]

	// The burst below inserts rebalN() items ALSO near c0, so the probe competes with
	// ~rebalN near-identical twins (jitter 0.01). This test asserts COVERAGE (the swap
	// never makes the probe invisible), not RANK, so topK must cover the whole
	// concentrated corpus — otherwise FHE score noise can push the self-match just out
	// of a small top-K even with perfect coverage (see clusteredFixture/clusterWonAcross,
	// which require topK == corpus size for the same reason).
	probeTopK := 1 + rebalN() + 64
	sc := s.client(t) // searcher client (created on the test goroutine)
	stop := make(chan struct{})
	var misses, searches atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			hits, err := sc.Search(ctx, probeVec, probeTopK)
			cancel()
			if err == nil {
				searches.Add(1)
				if !containsID(hits, probeID) {
					misses.Add(1)
					// Characterize: transient cross-tier observability window (an immediate
					// re-search finds it) vs. real loss (stays gone). Log the on-disk cell
					// state at the miss to correlate with a swap/merge.
					rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
					retry, rerr := sc.Search(rctx, probeVec, probeTopK)
					rcancel()
					t.Logf("MISS: probe absent from %d/%d hits (topK=%d); immediate re-search present=%v hits=%d; clusterCells=%d stagedFlat=%d",
						len(hits), probeTopK, probeTopK, rerr == nil && containsID(retry, probeID), len(retry), s.pvClusterCells(), s.pvStagedFlat())
				}
			}
		}
	}()

	insertNearCentroid(t, s, c, 0, rebalN(), 11) // burst triggers the swap
	s.waitFor(t, "cluster cell built", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })
	close(stop)
	wg.Wait()

	t.Logf("concurrent searches during rebalance: %d (misses %d)", searches.Load(), misses.Load())
	if m := misses.Load(); m > 0 {
		t.Errorf("probe id missing in %d/%d searches during rebalance (>=1 coverage violated)", m, searches.Load())
	}
}

// TestHarness_DeleteSearchRace: concurrent deletes and searches never error; after
// the race, deleted ids are gone and survivors remain.
func TestHarness_DeleteSearchRace(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 128})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	const m = 40
	ids, vecs := insertNearCentroid(t, s, c, 0, m, 12)

	dc := s.client(t)
	sc := s.client(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // deleter: even-indexed ids
		defer wg.Done()
		ctx := context.Background()
		for i := 0; i < m; i += 2 {
			_ = dc.Delete(ctx, ids[i])
		}
	}()
	go func() { // searcher: must never error during the deletes
		defer wg.Done()
		for i := range vecs {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			if _, err := sc.Search(ctx, vecs[i], 10); err != nil {
				t.Errorf("search %d during delete race: %v", i, err)
			}
			cancel()
		}
	}()
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := range ids {
		hits, err := c.Search(ctx, vecs[i], 10)
		if err != nil {
			t.Fatalf("post-race search %d: %v", i, err)
		}
		present := containsID(hits, ids[i])
		if i%2 == 0 && present {
			t.Errorf("deleted id %s still present after race", ids[i])
		}
		if i%2 == 1 && !present {
			t.Errorf("survivor id %s missing after race: %s", ids[i], summarizeHits(hits))
		}
	}
}
