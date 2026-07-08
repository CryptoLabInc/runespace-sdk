//go:build e2e

// crashedge_test.go: crash/recovery edges — torn-tail WAL recovery (F3), delete
// durability across a crash (D7), clean recovery from a crash mid-insert-burst with
// forward-orphan exclusion (B7), and a consistent reboot after a crash mid-register
// (A8). The exact sub-millisecond fsync↔commit boundaries can't be hit from a client
// without a production-code failpoint, so B7/D7/A8 drive a crash near the window and
// assert the durable RECOVERY invariant holds regardless of where the kill landed.
package e2e

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// tryRegister is the non-fatal form of register (usable from a goroutine, where
// t.Fatalf is illegal): generate the client keys once, then stream the eval keys.
func (s *serverInst) tryRegister() error {
	if !s.keysGen {
		if err := runespace.GenerateKeys(s.keyOpts()...); err != nil {
			return err
		}
		s.keysGen = true
	}
	c, err := runespace.Dial(s.addr, runespace.WithInsecure())
	if err != nil {
		return err
	}
	defer c.Close()
	keys, err := runespace.OpenKeys(s.keyOpts()...)
	if err != nil {
		return err
	}
	defer keys.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return c.RegisterKeys(ctx, keys)
}

// isReady reports whether the data plane is open (GetInfo.ready), non-fatally.
func (s *serverInst) isReady() bool {
	c, err := runespace.Dial(s.addr, runespace.WithInsecure())
	if err != nil {
		return false
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := c.Info(ctx)
	return err == nil && info.Ready
}

// bootLogHas reports whether the most recent boot's server log contains sub.
func (s *serverInst) bootLogHas(sub string) bool {
	b, err := os.ReadFile(filepath.Join(s.logDir(), fmt.Sprintf("server.%d.log", s.restarts-1)))
	return err == nil && strings.Contains(string(b), sub)
}

// insertBurstNonFatal inserts n items near base, ignoring errors — for a burst that
// is expected to be interrupted by a crash (runs in a goroutine, so no t.Fatalf).
func insertBurstNonFatal(c *runespace.Client, base []float32, n int, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := c.Insert(ctx, nearCentroid(base, rng, 0.01), ""); err != nil {
			return // server gone (crash) — stop
		}
	}
}

// TestHarness_TornTailRecovery (F3): a torn write at the active WAL tail is truncated
// on boot — the instance recovers (does not crash) and acked items survive.
func TestHarness_TornTailRecovery(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 256})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ids, vecs := insertNearCentroid(t, s, c, 0, 20, 30)
	s.kill()

	// Simulate a torn write: append a partial/garbage record to the active WAL tail.
	wal := filepath.Join(s.flatDir(), "active.wal")
	f, err := os.OpenFile(wal, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open wal %s: %v", wal, err)
	}
	if _, err := f.Write([]byte("\x00\x00\x00\x2aTORN-PARTIAL-RECORD-not-fsynced-tail")); err != nil {
		t.Fatalf("append torn tail: %v", err)
	}
	_ = f.Close()

	s.start() // must truncate the torn tail and come up, not crash
	s.waitReady(10 * time.Minute)
	c2 := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := range ids {
		hits, err := c2.Search(ctx, vecs[i], 20)
		if err != nil {
			t.Fatalf("post-torn-tail search %d: %v", i, err)
		}
		if !containsID(hits, ids[i]) {
			t.Errorf("acked id %s lost after torn-tail recovery: %s", ids[i], summarizeHits(hits))
		}
	}
}

// TestHarness_DeleteCrashStaysDeleted (D7): a delete tombstones durably before it
// removes the single, so a crash after the delete ack keeps the item excluded on
// reboot (and a non-deleted neighbour survives).
func TestHarness_DeleteCrashStaysDeleted(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 256})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	ids, vecs := insertNearCentroid(t, s, c, 0, 10, 41)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := c.Delete(ctx, ids[0]); err != nil {
		t.Fatalf("delete: %v", err)
	}
	s.kill()
	s.start()
	s.waitReady(10 * time.Minute)

	c2 := s.client(t)
	if hits, err := c2.Search(ctx, vecs[0], 20); err != nil {
		t.Fatalf("post-crash search: %v", err)
	} else if containsID(hits, ids[0]) {
		t.Errorf("deleted id %s resurfaced after crash: %s", ids[0], summarizeHits(hits))
	}
	if hits, err := c2.Search(ctx, vecs[1], 20); err != nil {
		t.Fatalf("neighbour search: %v", err)
	} else if !containsID(hits, ids[1]) {
		t.Errorf("non-deleted neighbour %s lost after crash: %s", ids[1], summarizeHits(hits))
	}
}

// TestHarness_CrashMidInsertRecovers (B7): a SIGKILL during a heavy insert burst must
// recover cleanly — acked items survive, and any forward orphan (a flat row whose
// insert crashed before its manifest commit) is excluded on boot (reconcileOrphans),
// never a phantom. The exact fsync↔commit window isn't hittable from a client, so
// this kills mid-burst; the recovery invariant must hold wherever the kill landed.
func TestHarness_CrashMidInsertRecovers(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 256})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute)

	c := s.client(t)
	base, baseVecs := insertNearCentroid(t, s, c, 0, 10, 42) // acked baseline
	c0 := s.centroidVec(t, 0)

	burstDone := make(chan struct{})
	go func() { defer close(burstDone); insertBurstNonFatal(c, c0, 500, 43) }()
	time.Sleep(800 * time.Millisecond) // let the burst get in flight
	s.kill()
	<-burstDone

	s.start() // clean recovery: must come up, not crash on a forward orphan
	s.waitReady(10 * time.Minute)
	c2 := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := range base {
		hits, err := c2.Search(ctx, baseVecs[i], 20)
		if err != nil {
			t.Fatalf("post-crash search %d: %v", i, err)
		}
		if !containsID(hits, base[i]) {
			t.Errorf("acked baseline id %s lost after mid-insert crash: %s", base[i], summarizeHits(hits))
		}
	}
	if s.bootLogHas("excluded orphan flat rows") {
		t.Logf("forward orphan(s) excluded on recovery (reconcileOrphans) — phantom-row invariant exercised")
	} else {
		t.Logf("no forward orphan this run (kill missed the fsync↔commit window) — recovery still clean")
	}
}

// TestHarness_RegisterCrashRecovers (A8): a SIGKILL during registration leaves no
// half-state — on reboot the instance is EITHER ready (persist completed) OR cleanly
// re-registerable. Either way it ends up usable.
func TestHarness_RegisterCrashRecovers(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8})
	s.start()
	if err := runespace.GenerateKeys(s.keyOpts()...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	s.keysGen = true // pre-generated; the goroutine register only streams

	regDone := make(chan struct{})
	go func() { defer close(regDone); _ = s.tryRegister() }()
	time.Sleep(700 * time.Millisecond) // kill mid-stream (the MM key is hundreds of MB)
	s.kill()
	<-regDone

	s.start()
	if s.isReady() {
		t.Logf("registration persisted before the crash → auto-ready on reboot")
	} else {
		s.register() // clean unregistered state → must succeed
		s.waitReady(10 * time.Minute)
		t.Logf("registration did not persist → re-registered cleanly on reboot")
	}
	// Usable either way.
	c := s.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	v := nearCentroid(s.centroidVec(t, 0), rand.New(rand.NewSource(1)), 0.01)
	if _, err := c.Insert(ctx, v, ""); err != nil {
		t.Errorf("instance not usable after register-crash recovery: %v", err)
	}
}
