//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// clusteredData is the shared clustered dataset: a fixed set of dual-rep items
// inserted and assembled ONCE per test binary. The server assembles a given
// instance only on its first clustered search, so every clustered test must draw
// from one assembled dataset — a second test inserting its own items would never
// see them folded into the cells (the lazy assembly already ran).
var clusteredData struct {
	once sync.Once
	ids  []string
	vecs [][]float32
	err  error
}

// clusteredFixture inserts the shared clustered dataset and forces the lazy
// per-cluster MM assembly, returning the ids and vectors (insert order). It uses
// its own short-lived client so the fixture outlives any single test's cleanup.
func clusteredFixture(t *testing.T) ([]string, [][]float32) {
	t.Helper()
	if !shared.ready {
		t.Skip("RUNESPACE_ADDR not set; skipping RuneSpace e2e")
	}
	if os.Getenv("RUNESPACE_CLUSTERED") == "" {
		t.Skip("RUNESPACE_CLUSTERED not set; skipping clustered e2e")
	}
	clusteredData.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		c, err := runespace.Dial(shared.addr, dialOpts()...)
		if err != nil {
			clusteredData.err = fmt.Errorf("dial: %w", err)
			return
		}
		defer c.Close()
		keys, err := runespace.OpenKeys(shared.keyOpts...)
		if err != nil {
			clusteredData.err = fmt.Errorf("OpenKeys: %w", err)
			return
		}
		defer keys.Close()
		c.UseKeys(keys)

		// R9 builds a cluster cell only once a centroid accumulates >= half a cell, so a
		// handful of scattered items never produces one. Route a concentrated burst at
		// centroid 0 (vectors crafted near it) to force a real cluster cell — the
		// instance must run a small flat.stage_threshold so the burst rotates flat cells
		// and wakes the rebalance worker.
		cl, rctx := rawClient(t)
		d, err := drainCentroids(cl, rctx)
		if err != nil {
			clusteredData.err = fmt.Errorf("GetCentroids: %w", err)
			return
		}
		if d.version == "" {
			clusteredData.err = fmt.Errorf("instance has no centroid set")
			return
		}
		base := d.centroids[0].GetVec()

		rng := rand.New(rand.NewSource(7))
		n := clusteredCorpusN()
		ids := make([]string, n)
		vecs := make([][]float32, n)
		for i := range ids {
			vecs[i] = nearCentroid(base, rng, 0.01)
			id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"idx":%d}`, i))
			if err != nil {
				clusteredData.err = fmt.Errorf("insert %d: %w", i, err)
				return
			}
			ids[i] = id
		}
		// Wait for the rebalance worker to build and route the cluster cell: poll a
		// search until it returns a cluster-tier hit.
		deadline := time.Now().Add(10 * time.Minute)
		for !clusteredHasClusterHit(ctx, c, vecs[0], n) {
			if time.Now().After(deadline) {
				clusteredData.err = fmt.Errorf("rebalance did not build/route a cluster cell within timeout")
				return
			}
			time.Sleep(2 * time.Second)
		}
		clusteredData.ids, clusteredData.vecs = ids, vecs
	})
	if clusteredData.err != nil {
		t.Fatalf("clustered fixture: %v", clusteredData.err)
	}
	return clusteredData.ids, clusteredData.vecs
}

// clusteredCorpusN is the near-centroid burst size for the clustered fixture; it
// must exceed half a cell (dim/2) so R9 seals a cluster cell. Default 600 (dim 1024);
// override with RUNESPACE_CLUSTERED_N.
func clusteredCorpusN() int {
	if s := os.Getenv("RUNESPACE_CLUSTERED_N"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 600
}

// clusteredHasClusterHit reports whether a search for vec yields a cluster-tier hit
// (used to wait for the rebalance worker to build and route the cluster cell).
func clusteredHasClusterHit(ctx context.Context, c *runespace.Client, vec []float32, topK int) bool {
	hits, err := c.Search(ctx, vec, topK)
	if err != nil {
		return false
	}
	for _, h := range hits {
		if h.ClusterID != runespace.FlatClusterID {
			return true
		}
	}
	return false
}

// clusterWonAcross searches each probe vector and reports how many had at least one
// hit attributed to a cluster (ClusterID != FlatClusterID). A single probe's
// self-match is a coin-flip between the flat and cluster copies of the same vector
// (identical dot product, different FHE noise; the merge breaks exact ties to
// flat), so the per-probe signal is ~50/50 even when the MM tier is sound — callers
// aggregate over several probes. requireSelf asserts each probe's own id is present
// in the returned hits (reliable only when topK covers the whole concentrated corpus,
// since the items are mutually near-identical).
func clusterWonAcross(t *testing.T, c *runespace.Client, ids []string, vecs [][]float32, probes []int, topK int, requireSelf bool) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	wins := 0
	for _, p := range probes {
		hits, err := c.Search(ctx, vecs[p], topK)
		if err != nil {
			t.Fatalf("Search probe %d: %v", p, err)
		}
		if requireSelf && !containsID(hits, ids[p]) {
			t.Errorf("probe %d: own id %s not present in top-%d: %s", p, ids[p], topK, summarizeHits(hits))
		}
		for _, h := range hits {
			if h.ClusterID != runespace.FlatClusterID {
				wins++
				break
			}
		}
	}
	return wins
}

// TestE2E_ClusteredInsertAssembleSearch is the full clustered-tier flow: the shared
// fixture inserts 64 dual-representation items (rmp_item + mm_item + routed
// cluster_id) and triggers the lazy per-cluster MM assembly. It verifies (1) a
// self-query ranks its own id first at a ~1.0 self-match, and (2) the clustered tier
// contributes competitive hits (so the assembly produced usable, correctly-scored
// indexes — not just the flat tier masking it). The server selects which clusters to
// probe (and how many) from the plaintext query; the client no longer routes, so a
// single client exercises the full merged flat+clustered path.
//
// (2) is checked in AGGREGATE over many probes: per probe, whether a cluster copy
// out-scores its flat twin is a coin-flip on FHE noise, so a single-probe check is
// inherently ~50/50. Across many probes a sound MM tier wins at least one with
// overwhelming probability, while a broken/garbage MM never out-scores flat.
//
// Requires RUNESPACE_CLUSTERED=1 (the target instance has a centroid set whose dim
// matches RUNESPACE_DIM).
func TestE2E_ClusteredInsertAssembleSearch(t *testing.T) {
	ids, vecs := clusteredFixture(t)

	// The server probes its configured clusters for every query, so one client covers
	// both checks: clusterWonAcross confirms each probe's own id resolves (presence)
	// and that the cluster tier is competitive, aggregated across probes. topK =
	// len(ids) returns the whole concentrated corpus, so presence is reliable despite
	// the items being mutually near-identical.
	c := e2eClient(t)
	probes := []int{7, 3, 11, 17, 23, 29, 37, 41, 47, 53, 59, 61}
	wins := clusterWonAcross(t, c, ids, vecs, probes, len(ids), true)
	t.Logf("clusters won >=1 hit in %d/%d probes", wins, len(probes))
	if wins == 0 {
		t.Error("no cluster won across any probe: the assembled MM tier produced nothing competitive")
	}
}
