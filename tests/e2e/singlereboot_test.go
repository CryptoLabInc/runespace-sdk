//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// Simulate TestHarness_DeleteCrashStaysDeleted for ModeRMP
func TestHarness_SingleDeleteCrashStaysDeleted(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, flatMode: "single"})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const n = 12
	rng := rand.New(rand.NewSource(808))
	vecs := make([][]float32, n)
	ids := make([]string, n)
	for i := range vecs {
		vecs[i] = genVec(s.dim, rng)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"i":%d}`, i))
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids[i] = id
	}

	// Delete
	deleted := map[int]bool{0: true, 5: true, 11: true}
	for i := range deleted {
		if err := c.Delete(ctx, ids[i]); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}

	// Crash
	s.restart()
	s.waitReady(10 * time.Minute)
	c2 := s.client(t)

	// Delete not applied
	for i := range vecs {
		hits, err := c2.Search(ctx, vecs[i], 20)
		if err != nil {
			t.Fatalf("post-crash search %d: %v", i, err)
		}
		if deleted[i] {
			if containsID(hits, ids[i]) {
				t.Errorf("deleted id %s (i=%d) resurfaced after crash: %s", ids[i], i, summarizeHits(hits))
			}
			continue
		}
		if len(hits) == 0 || hits[0].ID != ids[i] {
			t.Errorf("survivor i=%d self-match lost after crash: top=%s want %s", i, summarizeHits(hits), ids[i])
		}
	}

	nv := genVec(s.dim, rng)
	nid, err := c2.Insert(ctx, nv, `{"post":true}`)
	if err != nil {
		t.Fatalf("post-crash insert: %v", err)
	}
	if hits, err := c2.Search(ctx, nv, 5); err != nil {
		t.Fatalf("post-crash new-item search: %v", err)
	} else if len(hits) == 0 || hits[0].ID != nid {
		t.Errorf("post-crash new item not found: top=%s want %s", summarizeHits(hits), nid)
	}
}

func TestHarness_SinglePromotion(t *testing.T) {
	if testing.Short() {
		t.Skip("fills the 4096-item ModeSingle capacity; skipped under -short")
	}

	s := newServer(t, serverOpts{nprobe: 8, flatMode: "single", stageThreshold: 512})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Fill data until capacity
	const capacity = 4096
	rng := rand.New(rand.NewSource(808))
	for i := 0; i < capacity; i++ {
		insertRetryCap(ctx, t, c, genVec(s.dim, rng))
	}

	// Check if ModeSingle items promote to MM
	s.waitFor(t, "cluster cells built (items promoted)", 10*time.Minute, func() bool { return s.pvClusterCells() >= 1 })

	// Insert available again
	for i := 0; i < 8; i++ {
		if _, err := c.Insert(ctx, genVec(s.dim, rng), ""); err != nil {
			t.Fatalf("insert #%d past the old cap failed: %v", capacity+i, err)
		}
	}
}

// insertRetryCap inserts v, retrying while ModeSingle's flat cell is momentarily at
// capacity and the async rebalancer is still promoting covered items out of it. Any
// other failure, or failure to drain within the window, is fatal.
func insertRetryCap(ctx context.Context, t *testing.T, c *runespace.Client, v []float32) string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Minute)
	for {
		id, err := c.Insert(ctx, v, "")
		if err == nil {
			return id
		}

		if time.Now().After(deadline) {
			t.Fatalf("ModeSingle items seems not promoted: %v", err)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func TestHarness_SingleGracefulRestartPreservesData(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, flatMode: "single"})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const n = 8
	rng := rand.New(rand.NewSource(808))
	vecs := make([][]float32, n)
	ids := make([]string, n)
	for i := range vecs {
		vecs[i] = genVec(s.dim, rng)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"i":%d}`, i))
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids[i] = id
	}

	const gone = 3
	if err := c.Delete(ctx, ids[gone]); err != nil {
		t.Fatalf("delete: %v", err)
	}

	s.term()
	s.start()
	s.waitReady(10 * time.Minute)
	c2 := s.client(t)

	for i := range vecs {
		hits, err := c2.Search(ctx, vecs[i], 20)
		if err != nil {
			t.Fatalf("post-restart search %d: %v", i, err)
		}

		if i == gone {
			if containsID(hits, ids[i]) {
				t.Errorf("deleted id %s lost across restart: %s", ids[i], summarizeHits(hits))
			}
			continue
		}

		if len(hits) == 0 || hits[0].ID != ids[i] {
			t.Errorf("survivor i=%d lost across restart: top=%s want %s", i, summarizeHits(hits), ids[i])
		}
	}
}
