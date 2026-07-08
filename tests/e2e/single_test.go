//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestE2E_Single_InsertSearchMetadata(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, flatMode: "single"})
	s.start()
	s.register()
	s.waitReady(2 * time.Minute)
	c := s.client(t)

	const n = 20
	rng := rand.New(rand.NewSource(1))
	vecs := make([][]float32, n)
	ids := make([]string, n)
	ctx := context.Background()
	for i := range vecs {
		vecs[i] = genVec(s.dim, rng)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"idx":%d}`, i))
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids[i] = id
	}

	probe := n / 2
	hits, err := c.Search(ctx, vecs[probe], 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("search returned no hits")
	}
	if hits[0].ID != ids[probe] {
		t.Fatalf("top hit = %q; want %q (probe %d). hits=%+v", hits[0].ID, ids[probe], probe, hits)
	}
	if hits[0].Score < 0.9 {
		t.Errorf("self-match score = %.4f; want ~1.0", hits[0].Score)
	}

	var meta struct {
		Idx int `json:"idx"`
	}
	if err := json.Unmarshal([]byte(hits[0].Metadata), &meta); err != nil {
		t.Fatalf("top hit metadata %q not JSON: %v", hits[0].Metadata, err)
	}
	if meta.Idx != probe {
		t.Errorf("top hit metadata idx = %d; want %d", meta.Idx, probe)
	}
	t.Logf("ModeSingle e2e: n=%d probe=%d top=%s score=%.4f", n, probe, hits[0].ID, hits[0].Score)
}
