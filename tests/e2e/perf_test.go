//go:build e2e

// perf_test.go: a nightly-grade performance profile at production settings (the
// centroid artifact's nlist=4096, nprobe default 128). Gated by RUNESPACE_PERF (plus
// the process harness, RUNESPACE_BIN).
//
// The corpus is PERSISTENT and loaded ONCE: RUNESPACE_PERF_PVDIR (default
// /tmp/e2e-perf-corpus) is a stable PV that survives across runs, so a re-run at a
// different nprobe (a query-time setting) or sample size reuses the loaded data
// instead of re-inserting it — a dim-sized FHE load of 100k–1M is minutes to hours.
// The run only loads the delta needed to reach the largest tier; if the corpus is
// already at (or beyond) every tier, it just measures at the current size. Set
// RUNESPACE_PERF_RESET=1 to wipe and reload from scratch.
//
// It grows the corpus through size checkpoints (RUNESPACE_PERF_TIERS, default
// 512,10000,100000) and at each newly reached checkpoint measures insert / search /
// delete latency percentiles + throughput, writing a JSON artifact
// (RUNESPACE_PERF_OUT) for nightly trend tracking plus a t.Logf line. The regime falls
// out of the corpus size vs the stage threshold (dim): the 512 checkpoint stays
// flat-only (no rebalance), larger ones exercise the packed cluster tier — each
// profile records the live cell counts so the regime is explicit. It is NOT a latency
// pass/fail gate; it fails only on an operational error.
//
// Corpus is loaded concurrently (RUNESPACE_PERF_LOADERS, default 8). Tiers over 100k
// need RUNESPACE_PERF_HEAVY=1 (a CI-server nightly job).
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// perfStat is one (corpus checkpoint, op) latency profile; latencies in milliseconds.
type perfStat struct {
	Corpus       int     `json:"corpus"`        // live corpus size at measurement
	ClusterCells int     `json:"cluster_cells"` // cluster (MM) cells live at measurement
	StagedFlat   int     `json:"staged_flat"`   // staged flat cells (rebalance backlog)
	Op           string  `json:"op"`            // insert | search | delete
	N            int     `json:"n"`             // measured sample count
	QPS          float64 `json:"qps"`
	MeanMs       float64 `json:"mean_ms"`
	P50Ms        float64 `json:"p50_ms"`
	P95Ms        float64 `json:"p95_ms"`
	P99Ms        float64 `json:"p99_ms"`
	MaxMs        float64 `json:"max_ms"`
}

// perfReport is one run: the environment it ran under plus every profile.
type perfReport struct {
	Dim      int        `json:"dim"`
	Nprobe   int        `json:"nprobe"`
	UnixSec  int64      `json:"unix_sec"`
	SampleN  int        `json:"sample_n"`
	Tiers    []int      `json:"tiers"`
	Reused   bool       `json:"reused_corpus"` // true if it reused a persisted corpus
	Profiles []perfStat `json:"profiles"`
}

func durMs(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// perfTiers parses RUNESPACE_PERF_TIERS ("512,10000,100000") into a sorted list.
func perfTiers() []int {
	spec := os.Getenv("RUNESPACE_PERF_TIERS")
	if spec == "" {
		spec = "512,10000,100000"
	}
	var tiers []int
	for _, f := range strings.Split(spec, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n > 0 {
			tiers = append(tiers, n)
		}
	}
	sort.Ints(tiers)
	return tiers
}

// hasPersistedKeys reports whether the PV already holds eval keys from a prior run —
// so the server boots ready and the corpus can be reused without re-registering.
func (s *serverInst) hasPersistedKeys() bool {
	entries, err := os.ReadDir(s.evalKeyDir())
	return err == nil && len(entries) > 0
}

// measure summarizes latencies into a perfStat (reuses pct from runespace_test.go);
// the caller fills the corpus/cell context.
func measure(op string, lat []time.Duration, wall time.Duration) perfStat {
	st := perfStat{Op: op, N: len(lat)}
	if len(lat) == 0 {
		return st
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	var sum time.Duration
	for _, d := range lat {
		sum += d
	}
	st.QPS = float64(len(lat)) / wall.Seconds()
	st.MeanMs = durMs(sum / time.Duration(len(lat)))
	st.P50Ms, st.P95Ms, st.P99Ms = durMs(pct(lat, 50)), durMs(pct(lat, 95)), durMs(pct(lat, 99))
	st.MaxMs = durMs(lat[len(lat)-1])
	return st
}

// TestPerf_OpProfiles profiles insert/search/delete at each corpus checkpoint against
// a persistent, load-once corpus, emitting a JSON artifact for nightly trend tracking.
func TestPerf_OpProfiles(t *testing.T) {
	if os.Getenv("RUNESPACE_PERF") == "" {
		t.Skip("RUNESPACE_PERF not set; skipping perf profile")
	}
	tiers := perfTiers()
	if len(tiers) == 0 {
		t.Fatal("RUNESPACE_PERF_TIERS parsed to no positive sizes")
	}
	if max := tiers[len(tiers)-1]; max > 100_000 && os.Getenv("RUNESPACE_PERF_HEAVY") == "" {
		t.Skipf("largest tier %d exceeds 100k; set RUNESPACE_PERF_HEAVY=1 to run (a dim-sized FHE load of this size is a CI-server job)", max)
	}
	n := envInt("RUNESPACE_PERF_N", 200)
	loaders := envInt("RUNESPACE_PERF_LOADERS", 8)
	nprobe := envInt("RUNESPACE_PERF_NPROBE", 128) // production-level probing (nlist=4096)

	pvDir := os.Getenv("RUNESPACE_PERF_PVDIR")
	if pvDir == "" {
		pvDir = "/tmp/e2e-perf-corpus"
	}
	if os.Getenv("RUNESPACE_PERF_RESET") != "" {
		if err := os.RemoveAll(pvDir); err != nil {
			t.Fatalf("reset perf pv: %v", err)
		}
	}

	// Persistent PV (default stage threshold = dim): the corpus is loaded once and
	// reused across runs; a corpus below the threshold stays flat-only, above it feeds
	// the packed cluster tier.
	s := newServer(t, serverOpts{nprobe: nprobe, persistPV: pvDir})
	reused := s.hasPersistedKeys()
	s.start()
	if reused {
		s.keysGen = true // keys persisted in the PV; skip GenerateKeys/register
		s.waitReady(10 * time.Minute)
		t.Logf("reusing persisted corpus at %s (singles=%d)", pvDir, s.pvSingles())
	} else {
		s.register()
		s.waitReady(10 * time.Minute)
	}
	c := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	report := perfReport{Dim: s.dim, Nprobe: nprobe, UnixSec: time.Now().Unix(), SampleN: n, Tiers: tiers, Reused: reused}

	loaded := s.pvSingles() // live corpus already present (durable singles ~= item count)
	measuredAny := false
	for _, cp := range tiers {
		if loaded >= cp {
			continue // already at/beyond this checkpoint (a prior run grew past it)
		}
		loadTo(t, s, cp, &loaded, loaders)
		measureAt(t, ctx, &report, c, s, cp, n)
		measuredAny = true
	}
	if !measuredAny {
		// Corpus already meets every tier (reuse) — measure at its current size.
		measureAt(t, ctx, &report, c, s, loaded, n)
	}

	writePerfReport(t, s, report)
}

// measureAt profiles search/insert/delete at the current corpus and appends the
// results (tagged with the live cell counts) to the report. search uses fresh random
// queries (latency is fan-out, not recall, so real vectors are unneeded); insert
// samples fresh rows and delete removes exactly those, so the corpus nets ~unchanged.
func measureAt(t *testing.T, ctx context.Context, report *perfReport, c *runespace.Client, s *serverInst, corpus, n int) {
	t.Helper()
	settle(s, 3*time.Minute) // let the rebalance backlog drain so a clustered tier is settled
	cc, sf := s.pvClusterCells(), s.pvStagedFlat()
	rng := rand.New(rand.NewSource(int64(corpus)*1315423911 + 1))

	// search — fresh random queries (read-only).
	schLat := make([]time.Duration, 0, n)
	w0 := time.Now()
	for i := 0; i < n; i++ {
		ti := time.Now()
		if _, err := c.Search(ctx, genVec(s.dim, rng), 10); err != nil {
			t.Fatalf("search @%d: %v", corpus, err)
		}
		schLat = append(schLat, time.Since(ti))
	}
	recPerf(t, report, corpus, cc, sf, measure("search", schLat, time.Since(w0)))

	// insert — a sequential sample; keep the ids to delete next.
	insLat := make([]time.Duration, 0, n)
	ids := make([]string, 0, n)
	w0 = time.Now()
	for i := 0; i < n; i++ {
		ti := time.Now()
		id, err := c.Insert(ctx, genVec(s.dim, rng), "")
		if err != nil {
			t.Fatalf("insert @%d: %v", corpus, err)
		}
		insLat = append(insLat, time.Since(ti))
		ids = append(ids, id)
	}
	recPerf(t, report, corpus, cc, sf, measure("insert", insLat, time.Since(w0)))

	// delete — exactly the just-inserted ids (so the corpus nets back to `corpus`).
	delLat := make([]time.Duration, 0, len(ids))
	w0 = time.Now()
	for _, id := range ids {
		ti := time.Now()
		if err := c.Delete(ctx, id); err != nil {
			t.Fatalf("delete @%d: %v", corpus, err)
		}
		delLat = append(delLat, time.Since(ti))
	}
	recPerf(t, report, corpus, cc, sf, measure("delete", delLat, time.Since(w0)))
}

// recPerf tags a profile with its corpus/cell context, appends it, and logs it.
func recPerf(t *testing.T, report *perfReport, corpus, clusterCells, stagedFlat int, st perfStat) {
	st.Corpus, st.ClusterCells, st.StagedFlat = corpus, clusterCells, stagedFlat
	report.Profiles = append(report.Profiles, st)
	t.Logf("corpus=%d cells=%d staged=%d %s: n=%d qps=%.0f mean=%.2fms p50=%.2f p95=%.2f p99=%.2f max=%.2f",
		st.Corpus, st.ClusterCells, st.StagedFlat, st.Op, st.N, st.QPS, st.MeanMs, st.P50Ms, st.P95Ms, st.P99Ms, st.MaxMs)
}

// loadTo grows the loaded corpus to target with concurrent, unmeasured inserts of
// scattered vectors. Fatal on a load error.
func loadTo(t *testing.T, s *serverInst, target int, loaded *int, loaders int) {
	t.Helper()
	remaining := target - *loaded
	if remaining <= 0 {
		return
	}
	if loaders < 1 {
		loaders = 1
	}
	t.Logf("loading %d rows: %d -> %d (%d loaders)", remaining, *loaded, target, loaders)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	for w := 0; w < loaders; w++ {
		cnt := remaining / loaders
		if w == loaders-1 {
			cnt = remaining - (remaining/loaders)*(loaders-1)
		}
		wg.Add(1)
		go func(w, cnt int) {
			defer wg.Done()
			wc, err := runespace.Dial(s.addr, runespace.WithInsecure())
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			defer wc.Close()
			wk, err := runespace.OpenKeys(s.keyOpts()...)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			defer wk.Close()
			wc.UseKeys(wk)
			rng := rand.New(rand.NewSource(int64(1_000_000*(w+1)) + int64(*loaded)))
			for i := 0; i < cnt; i++ {
				if _, err := wc.Insert(context.Background(), genVec(s.dim, rng), ""); err != nil {
					errOnce.Do(func() { firstErr = err })
					return
				}
			}
		}(w, cnt)
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("load to %d: %v", target, firstErr)
	}
	*loaded = target
}

// settle waits (best-effort, non-fatal) for the rebalance backlog to drain so a
// clustered checkpoint measures a settled tier; it returns early once staged flat
// cells hit zero, or when the timeout lapses (the recorded cell counts show the state).
func settle(s *serverInst, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.pvStagedFlat() == 0 {
			return
		}
		time.Sleep(time.Second)
	}
}

// writePerfReport emits the run as indented JSON to RUNESPACE_PERF_OUT (a file path)
// or, when unset, to <logDir>/perf.<unixSec>.json, and logs the path.
func writePerfReport(t *testing.T, s *serverInst, report perfReport) {
	t.Helper()
	out := os.Getenv("RUNESPACE_PERF_OUT")
	if out == "" {
		out = filepath.Join(s.logDir(), fmt.Sprintf("perf.%d.json", report.UnixSec))
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal perf report: %v", err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write perf report %s: %v", out, err)
	}
	t.Logf("perf report (%d profiles) written to %s", len(report.Profiles), out)
}
