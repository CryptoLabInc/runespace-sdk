//go:build e2e

// load_test.go (W8): an incremental capacity ramp on the real machine. There is NO
// fixed target — it inserts in batches (routed near one centroid to drive real
// rebalance) and records insert throughput, search latency percentiles, physical
// cell count, the staged-flat backlog (does compaction keep up with ingest?), and
// server RSS, stopping at RUNESPACE_LOAD_N or when the backlog runs away (the
// practical ceiling on this box). Gated on RUNESPACE_BIN + RUNESPACE_LOAD_N.
package e2e

import (
	"context"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHarness_CapacityRamp(t *testing.T) {
	target := 0
	if v := os.Getenv("RUNESPACE_LOAD_N"); v != "" {
		target, _ = strconv.Atoi(v)
	}
	if target <= 0 {
		t.Skip("RUNESPACE_LOAD_N not set; skipping capacity ramp")
	}
	batch := envInt("RUNESPACE_LOAD_BATCH", 1000)
	backlogCap := envInt("RUNESPACE_LOAD_BACKLOG_CAP", 64)

	s := newServer(t, serverOpts{nprobe: 16, stageThreshold: 1024})
	s.start()
	s.register()
	s.waitReady(15 * time.Minute)

	c := s.client(t)
	base := s.centroidVec(t, 0) // ramp near one centroid to actually drive rebalance
	rng := rand.New(rand.NewSource(7))
	ctx := context.Background()

	var firstID string
	var firstVec []float32
	inserted := 0
	for inserted < target {
		k := batch
		if inserted+k > target {
			k = target - inserted
		}
		start := time.Now()
		for i := 0; i < k; i++ {
			v := nearCentroid(base, rng, 0.05)
			id, err := c.Insert(ctx, v, "")
			if err != nil {
				t.Fatalf("insert at N=%d: %v", inserted+i, err)
			}
			if firstID == "" {
				firstID, firstVec = id, v
			}
		}
		inserted += k
		insTPS := float64(k) / time.Since(start).Seconds()

		var lat []time.Duration
		for i := 0; i < 20; i++ {
			ti := time.Now()
			if _, err := c.Search(ctx, nearCentroid(base, rng, 0.05), 10); err == nil {
				lat = append(lat, time.Since(ti))
			}
		}
		hits, _ := c.Search(ctx, firstVec, 10)
		found := containsID(hits, firstID)

		t.Logf("N=%d insTPS=%.0f sP50=%s sP95=%s | cells=%d stagedFlat=%d singles=%d rssMB=%d firstFound=%v",
			inserted, insTPS, pctOf(lat, 50), pctOf(lat, 95),
			s.pvClusterCells(), s.pvStagedFlat(), s.pvSingles(), s.rssMB(), found)
		if !found {
			t.Errorf("first id lost at N=%d (coverage broke under load)", inserted)
		}
		if s.pvStagedFlat() > backlogCap {
			t.Logf("staged-flat backlog %d > cap %d at N=%d — compaction is falling behind; "+
				"practical ceiling reached on this box, stopping", s.pvStagedFlat(), backlogCap, inserted)
			break
		}
	}
	t.Logf("capacity ramp finished at N=%d", inserted)
}

// rssMB returns the server process RSS in MiB (best-effort via ps; 0 on failure).
func (s *serverInst) rssMB() int {
	if s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(s.cmd.Process.Pid)).Output()
	if err != nil {
		return 0
	}
	kb, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return kb / 1024
}

// pctOf returns the p-th percentile of durations (0 for an empty sample).
func pctOf(d []time.Duration, p int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), d...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := (p*len(cp))/100 - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}
