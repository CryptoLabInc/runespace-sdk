//go:build e2e

// perf_remote_test.go: a RUNESPACE_ADDR-driven performance profile for a server that
// runs OUT OF PROCESS — e.g. a resource-constrained Docker container. It is the remote
// twin of perf_test.go: same insert/search/delete latency + throughput measurement at
// each RUNESPACE_PERF_TIERS checkpoint, but instead of owning a RUNESPACE_BIN subprocess
// and reading its PV, it attaches to the shared instance TestMain registered (the vault
// role) and drives it purely over the SDK. The server's PV is not readable across the
// process/container boundary, so cluster/staged cell counts are reported as -1; at tiers
// below the stage threshold (dim) the corpus is flat-only anyway.
//
// Latency here is the end-to-end SDK round-trip a client observes: client-side FHE
// encode of the query/row (on the caller's host, unconstrained) + gRPC + server compute
// (under whatever the container is limited to) + client-side decode of the result blob.
//
// Gated on RUNESPACE_ADDR (TestMain must have registered keys) + RUNESPACE_PERF. The
// target must start UNREGISTERED and, for clean per-tier sizes, EMPTY (a fresh corpus).
//
//	RUNESPACE_ADDR=127.0.0.1:51024 RUNESPACE_INSECURE=1 RUNESPACE_DIM=1024 \
//	  RUNESPACE_PERF=1 RUNESPACE_PERF_TIERS=100,500,1000 RUNESPACE_PERF_N=200 \
//	  go test -tags e2e -run TestPerf_Remote ./e2e/ -timeout 2h -v
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// TestPerf_Remote profiles insert/search/delete against a remote (possibly
// resource-constrained) instance across the RUNESPACE_PERF_TIERS checkpoints, writing a
// JSON artifact (RUNESPACE_PERF_OUT, else $TMPDIR/perf-remote.<unix>.json).
func TestPerf_Remote(t *testing.T) {
	if !shared.ready {
		t.Skip("RUNESPACE_ADDR not set; skipping remote perf profile")
	}
	if os.Getenv("RUNESPACE_PERF") == "" {
		t.Skip("RUNESPACE_PERF not set; skipping remote perf profile")
	}
	tiers := perfTiers()
	if len(tiers) == 0 {
		t.Fatal("RUNESPACE_PERF_TIERS parsed to no positive sizes")
	}
	n := envInt("RUNESPACE_PERF_N", 200)
	loaders := envInt("RUNESPACE_PERF_LOADERS", 8)

	c := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	// Real traffic trickles in, so a just-registered instance has time for the boot-time
	// centroid-parse transient to be scavenged and the key-write page cache to be reclaimed
	// before load. Wait RUNESPACE_PERF_SETTLE_SEC (default 0) to mimic that quiet window
	// instead of hammering a cold, cache-heavy instance the instant keys register.
	if secs := envInt("RUNESPACE_PERF_SETTLE_SEC", 0); secs > 0 {
		t.Logf("settling %ds before measurement", secs)
		time.Sleep(time.Duration(secs) * time.Second)
	}

	report := perfReport{
		Dim:     shared.dim,
		Nprobe:  envInt("RUNESPACE_PERF_NPROBE", 128), // informational: server-side config
		UnixSec: time.Now().Unix(),
		SampleN: n,
		Tiers:   tiers,
	}

	// Corpus grows cumulatively from empty through each checkpoint (a fresh instance
	// starts at 0). search is measured before the insert/delete sample, so the reported
	// search size is the loaded corpus; the sampled rows are deleted (soft delete leaves
	// a tombstone that later, larger-tier scans still traverse until compaction).
	loaded := 0
	for _, cp := range tiers {
		if loaded < cp {
			loadToRemote(t, cp, &loaded, loaders)
		}
		measureAtRemote(t, ctx, &report, c, cp, n)
	}
	writeReportRemote(t, report)
}

// measureAtRemote profiles search/insert/delete at the current corpus and appends the
// results to the report. Mirrors perf_test.go's measureAt without the PV introspection
// (cell counts are unknown across the boundary → -1).
func measureAtRemote(t *testing.T, ctx context.Context, report *perfReport, c *runespace.Client, corpus, n int) {
	t.Helper()
	rng := rand.New(rand.NewSource(int64(corpus)*1315423911 + 1))

	// search — fresh random queries (read-only; latency is fan-out, not recall).
	schLat := make([]time.Duration, 0, n)
	w0 := time.Now()
	for i := 0; i < n; i++ {
		ti := time.Now()
		if _, err := c.Search(ctx, genVec(shared.dim, rng), 10); err != nil {
			t.Fatalf("search @%d: %v", corpus, err)
		}
		schLat = append(schLat, time.Since(ti))
	}
	recPerfRemote(t, report, corpus, measure("search", schLat, time.Since(w0)))

	// insert — a sequential sample; keep the ids to delete next. RUNESPACE_PERF_WRITE_N
	// (default n) sizes the write sample separately from the read sample, so the physical
	// row count can be held below the flat stage threshold (dim) when profiling the pure
	// flat tier near its dim-row ceiling — write churn there would rotate a cell and
	// trigger the multi-GB MM staging/assemble.
	writeN := envInt("RUNESPACE_PERF_WRITE_N", n)
	insLat := make([]time.Duration, 0, writeN)
	ids := make([]string, 0, writeN)
	w0 = time.Now()
	for i := 0; i < writeN; i++ {
		ti := time.Now()
		id, err := c.Insert(ctx, genVec(shared.dim, rng), "")
		if err != nil {
			t.Fatalf("insert @%d: %v", corpus, err)
		}
		insLat = append(insLat, time.Since(ti))
		ids = append(ids, id)
	}
	recPerfRemote(t, report, corpus, measure("insert", insLat, time.Since(w0)))

	// delete — exactly the just-inserted ids (so the live corpus nets back to `corpus`).
	delLat := make([]time.Duration, 0, len(ids))
	w0 = time.Now()
	for _, id := range ids {
		ti := time.Now()
		if err := c.Delete(ctx, id); err != nil {
			t.Fatalf("delete @%d: %v", corpus, err)
		}
		delLat = append(delLat, time.Since(ti))
	}
	recPerfRemote(t, report, corpus, measure("delete", delLat, time.Since(w0)))
}

// recPerfRemote tags a profile with its corpus (cell counts unknown remotely → -1),
// appends it, and logs it.
func recPerfRemote(t *testing.T, report *perfReport, corpus int, st perfStat) {
	st.Corpus, st.ClusterCells, st.StagedFlat = corpus, -1, -1
	report.Profiles = append(report.Profiles, st)
	t.Logf("corpus=%d %s: n=%d qps=%.0f mean=%.2fms p50=%.2f p95=%.2f p99=%.2f max=%.2f",
		st.Corpus, st.Op, st.N, st.QPS, st.MeanMs, st.P50Ms, st.P95Ms, st.P99Ms, st.MaxMs)
}

// loadToRemote grows the loaded corpus to target with concurrent, unmeasured inserts of
// scattered vectors over the shared key set. Fatal on a load error.
func loadToRemote(t *testing.T, target int, loaded *int, loaders int) {
	t.Helper()
	remaining := target - *loaded
	if remaining <= 0 {
		return
	}
	if loaders < 1 {
		loaders = 1
	}
	t.Logf("loading %d rows: %d -> %d (%d loaders)", remaining, *loaded, target, loaders)
	base := *loaded
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
			wc, err := runespace.Dial(shared.addr, dialOpts()...)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			defer wc.Close()
			wk, err := runespace.OpenKeys(shared.keyOpts...)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			defer wk.Close()
			wc.UseKeys(wk)
			rng := rand.New(rand.NewSource(int64(1_000_000*(w+1)) + int64(base)))
			for i := 0; i < cnt; i++ {
				if _, err := wc.Insert(context.Background(), genVec(shared.dim, rng), ""); err != nil {
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

// writeReportRemote emits the run as indented JSON to RUNESPACE_PERF_OUT (a file path)
// or, when unset, to $TMPDIR/perf-remote.<unixSec>.json, and logs the path.
func writeReportRemote(t *testing.T, report perfReport) {
	t.Helper()
	out := os.Getenv("RUNESPACE_PERF_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), fmt.Sprintf("perf-remote.%d.json", report.UnixSec))
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
