//go:build e2e

// flatmode_compare_test.go: runs the SAME insert + self-search workload against the flat
// tier in each mode — RMP (the LSM/consolidated default) and single (standalone FLAT,
// ModeSingle) — and logs a side-by-side comparison: the flat eval-key size the client
// generated (the headline RMP-vs-FLAT tradeoff), key registration time, insert/search
// wall time, and the self-match score. Both modes must rank the probe's own id first.
//
// Heavy: two server instances, two full keygens (each includes the MM eval key). Opt-in
// via RUNESPACE_BIN. Same corpus (seed 1) in both modes for an apples-to-apples read.
package e2e

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestE2E_FlatModeCompare(t *testing.T) {
	const n = 4096 // maximum capacity in single CELL <= DEGREE
	const probe = n / 2
	for _, mode := range []string{"rmp", "single"} {
		t.Run(mode, func(t *testing.T) {
			s := newServer(t, serverOpts{nprobe: 8, flatMode: mode})
			s.start()

			tReg := time.Now()
			s.register()
			s.waitReady(5 * time.Minute)
			regDur := time.Since(tReg)

			c := s.client(t)
			rng := rand.New(rand.NewSource(808))
			vecs := make([][]float32, n)
			ids := make([]string, n)
			ctx := context.Background()

			tIns := time.Now()
			for i := range vecs {
				vecs[i] = genVec(s.dim, rng)

				id, err := c.Insert(ctx, vecs[i], "")
				if err != nil {
					t.Fatalf("[%s] insert %d: %v", mode, i, err)
				}

				ids[i] = id
			}
			insDur := time.Since(tIns)

			// Warm-up (build cache for ModeSingle)
			for i := 0; i < 2; i++ {
				if _, err := c.Search(ctx, vecs[probe], 10); err != nil {
					t.Fatalf("[%s] warmup search: %v", mode, err)
				}
			}

			const rounds = 5
			ts := time.Now()
			hits, err := c.Search(ctx, vecs[probe], 10)
			if err != nil {
				t.Fatalf("[%s] search: %v", mode, err)
			}

			for i := 1; i < rounds; i++ {
				if hits, err = c.Search(ctx, vecs[probe], 10); err != nil {
					t.Fatalf("[%s] search: %v", mode, err)
				}
			}
			searchAvg := time.Since(ts) / rounds

			if len(hits) == 0 || hits[0].ID != ids[probe] {
				t.Fatalf("[%s] top hit = %+v; want id %q (probe %d)", mode, hits, ids[probe], probe)
			}
			if hits[0].Score < 0.9 {
				t.Errorf("[%s] self-match score = %.4f; want ~1.0", mode, hits[0].Score)
			}

			t.Logf("[%-6s] flat_eval_key=%7.2f MB  register=%-9v insert(n=%d)=%-9v (%v/op)  search(warm)=%-8v top score=%.4f",
				mode, float64(flatEvalKeySize(t, s))/(1<<20), regDur.Round(time.Millisecond),
				n, insDur.Round(time.Millisecond), (insDur / n).Round(time.Millisecond),
				searchAvg.Round(time.Millisecond), hits[0].Score)
		})
	}
}

func flatEvalKeySize(t *testing.T, s *serverInst) int64 {
	t.Helper()

	for _, name := range []string{"EvalKey.bin", "EvalKey.json"} {
		if fi, err := os.Stat(filepath.Join(s.keyDir, name)); err == nil {
			return fi.Size()
		}
	}

	return 0
}
