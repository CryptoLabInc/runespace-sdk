//go:build e2e

// harness_test.go: a process-lifecycle harness that OWNS a runespace server
// subprocess, for the crash / recovery / rebalance / load suites. The functional
// black-box tests (runespace_test.go etc.) attach to an externally-run server via
// RUNESPACE_ADDR; this harness instead launches `$RUNESPACE_BIN --config <tmp>`
// against an isolated temp PV, so a test can SIGKILL/restart it and inspect the
// on-disk state directly — no admin RPC, no production-code failpoints (the
// recovery contract is a pure function of durable state, so the externally
// observable durable artifacts are exactly the boundaries recovery distinguishes).
//
// Gated on two envs; the test skips when they are unset:
//
//	RUNESPACE_BIN        path to a built runespace server binary
//	RUNESPACE_CENTROIDS  path to the centroid artifact (runespace/configs/centroids/default.json)
//
// The cluster tier is always configured (flat-only insert was removed), so a
// centroid set is mandatory. dim is fixed by the artifact (default.json = 1024);
// RUNESPACE_DIM must match it. The client keys are generated at dim, so a harness
// run is heavy (hundreds-of-MB MM eval key) — it is opt-in by design.
package e2e

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// harnessEnv resolves RUNESPACE_BIN + RUNESPACE_CENTROIDS and skips the test when
// either is unset.
func harnessEnv(t *testing.T) (bin, centroids string) {
	t.Helper()
	bin = os.Getenv("RUNESPACE_BIN")
	if bin == "" {
		t.Skip("RUNESPACE_BIN not set; skipping process-harness e2e")
	}
	centroids = os.Getenv("RUNESPACE_CENTROIDS")
	if centroids == "" {
		t.Skip("RUNESPACE_CENTROIDS not set (path to configs/centroids/default.json); skipping")
	}
	if _, err := os.Stat(centroids); err != nil {
		t.Fatalf("RUNESPACE_CENTROIDS %q: %v", centroids, err)
	}
	return bin, centroids
}

// serverOpts tunes one instance. stageThreshold 0 ⇒ the server default (dim); a
// small value forces flat-cell rotation (and thus the rebalance trigger) with few
// rows, so a test can exercise staging without inserting dim items.
type serverOpts struct {
	nprobe         int
	stageThreshold int
	// reassembleLiveFraction sets cluster.reassemble_live_fraction: re-pack a big
	// (append-only) cell once deletes hollow its live rows to this fraction or below,
	// when a pass would free a block. 0 ⇒ omit (the server default, 0.5).
	reassembleLiveFraction float64
	// persistPV, when set, is a stable PV root REUSED across runs (never wiped) — the
	// perf suite loads a corpus once here and reuses it on later runs. Empty ⇒ the
	// default isolated, auto-cleaned temp PV.
	persistPV string
	// flatMode sets flat.mode ("rmp" | "single"); empty ⇒ omit (the server default, rmp).
	// single makes the flat tier hard-delete and reassemble live-only.
	flatMode string
}

// serverInst is one runespace server process bound to an isolated temp PV. The
// same PV survives restart() so recovery can be asserted. stop() (registered via
// t.Cleanup) force-kills a still-running process.
type serverInst struct {
	t         *testing.T
	bin       string
	centroids string
	dim       int
	opts      serverOpts

	dir     string // PV root (t.TempDir): flat/ cluster/ evalkeys/ clientkeys/ manifest.db config.yaml
	cfgPath string
	keyDir  string
	addr    string
	port    int

	cmd      *exec.Cmd
	done     chan struct{} // closed when the process exits
	waitErr  error
	restarts int
	keysGen  bool

	// centroid set cached once (centVecs[i] is centroid i's vector), so a test can
	// craft vectors that route to a chosen cluster. See centroidVec (harness_util).
	centVecs    [][]float32
	centVersion string
}

// newServer allocates an isolated instance (temp PV, free port, written config). It
// does not start the process (call start) or register keys (call register).
func newServer(t *testing.T, opts serverOpts) *serverInst {
	t.Helper()
	bin, centroids := harnessEnv(t)
	dir := t.TempDir()
	switch {
	case opts.persistPV != "":
		// Reused across runs: create if missing, never wipe (the corpus persists).
		dir = opts.persistPV
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir persist pv: %v", err)
		}
	case os.Getenv("RUNESPACE_HARNESS_PVDIR") != "":
		// Optional stable PV root for inspecting on-disk state after a run; wiped fresh.
		dir = filepath.Join(os.Getenv("RUNESPACE_HARNESS_PVDIR"), t.Name())
		_ = os.RemoveAll(dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir pv: %v", err)
		}
	}
	s := &serverInst{
		t: t, bin: bin, centroids: centroids, dim: envDim(), opts: opts,
		dir:     dir,
		cfgPath: filepath.Join(dir, "runespace.yaml"),
		keyDir:  filepath.Join(dir, "clientkeys"),
		port:    freePort(t),
	}
	s.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port))
	for _, d := range []string{s.flatDir(), s.clusterDir(), s.evalKeyDir(), s.keyDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	s.writeConfig()
	t.Cleanup(s.stop)
	return s
}

func (s *serverInst) flatDir() string      { return filepath.Join(s.dir, "flat") }
func (s *serverInst) clusterDir() string   { return filepath.Join(s.dir, "cluster") }
func (s *serverInst) evalKeyDir() string   { return filepath.Join(s.dir, "evalkeys") }
func (s *serverInst) manifestPath() string { return filepath.Join(s.dir, "manifest.db") }

// writeConfig emits the YAML the server reads. The cluster tier is always
// configured: centroid_config_path + a positive nprobe are mandatory.
func (s *serverInst) writeConfig() {
	stage := ""
	if s.opts.stageThreshold > 0 {
		stage = fmt.Sprintf("\n  stage_threshold: %d", s.opts.stageThreshold)
	}
	reassemble := ""
	if s.opts.reassembleLiveFraction > 0 {
		reassemble = fmt.Sprintf("\n  reassemble_live_fraction: %g", s.opts.reassembleLiveFraction)
	}
	mode := ""
	if s.opts.flatMode != "" {
		mode = fmt.Sprintf("\n  mode: %s", s.opts.flatMode)
	}
	cfg := fmt.Sprintf(`server:
  grpc:
    host: 127.0.0.1
    port: %d
  shutdown_grace_period: 5s
engine:
  dim: %d
  eval_key_path: %s
flat:
  dir: %s%s%s
cluster:
  dir: %s
  centroid_config_path: %s
  nprobe: %d%s
manifest:
  path: %s
log:
  level: info
  format: json
`, s.port, s.dim, s.evalKeyDir(), s.flatDir(), stage, mode, s.clusterDir(), s.centroids, s.opts.nprobe, reassemble, s.manifestPath())
	if err := os.WriteFile(s.cfgPath, []byte(cfg), 0o644); err != nil {
		s.t.Fatalf("write config: %v", err)
	}
}

// start launches the server and blocks until its gRPC port answers GetInfo (it
// does not wait for ready — keys may be unregistered). A process group is set so a
// SIGKILL reaps any child cleanly.
func (s *serverInst) start() {
	s.t.Helper()
	if s.cmd != nil {
		s.t.Fatal("server already started")
	}
	logPath := filepath.Join(s.logDir(), fmt.Sprintf("server.%d.log", s.restarts))
	logf, err := os.Create(logPath)
	if err != nil {
		s.t.Fatalf("create server log: %v", err)
	}
	cmd := exec.Command(s.bin, "--config", s.cfgPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		s.t.Fatalf("start server: %v", err)
	}
	s.cmd = cmd
	s.restarts++
	done := make(chan struct{})
	s.done = done
	go func() { s.waitErr = cmd.Wait(); _ = logf.Close(); close(done) }()
	s.waitListening(45 * time.Second)
}

// waitListening polls GetInfo until the port answers, failing fast if the process
// dies during startup.
func (s *serverInst) waitListening(timeout time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.exited() {
			s.t.Fatalf("server exited during startup (err=%v); log tail:\n%s", s.waitErr, s.logTail())
		}
		c, err := runespace.Dial(s.addr, runespace.WithInsecure())
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, ierr := c.Info(ctx)
			cancel()
			_ = c.Close()
			if ierr == nil {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	s.t.Fatalf("server did not start listening within %s; log tail:\n%s", timeout, s.logTail())
}

// register generates the client key set once and registers the PUBLIC eval keys
// with the instance (the vault role). The server persists them to its PV, so a
// later restart() reloads them and comes up ready without re-registering.
func (s *serverInst) register() {
	s.t.Helper()
	if !s.keysGen {
		if err := runespace.GenerateKeys(s.keyOpts()...); err != nil {
			s.t.Fatalf("GenerateKeys: %v", err)
		}
		s.keysGen = true
	}
	c, err := runespace.Dial(s.addr, runespace.WithInsecure())
	if err != nil {
		s.t.Fatalf("dial for register: %v", err)
	}
	defer c.Close()
	keys, err := runespace.OpenKeys(s.keyOpts()...)
	if err != nil {
		s.t.Fatalf("OpenKeys: %v", err)
	}
	defer keys.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := c.RegisterKeys(ctx, keys); err != nil {
		s.t.Fatalf("RegisterKeys: %v", err)
	}
}

// waitReady polls GetInfo until the data plane is open (eval keys loaded).
func (s *serverInst) waitReady(timeout time.Duration) {
	s.t.Helper()
	c, err := runespace.Dial(s.addr, runespace.WithInsecure())
	if err != nil {
		s.t.Fatalf("dial for ready: %v", err)
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.exited() {
			s.t.Fatalf("server exited while waiting for ready (err=%v); log tail:\n%s", s.waitErr, s.logTail())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		info, err := c.Info(ctx)
		cancel()
		if err == nil && info.Ready {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.t.Fatalf("server not ready within %s", timeout)
}

func (s *serverInst) keyOpts() []runespace.KeysOption {
	opts := []runespace.KeysOption{
		runespace.WithKeyPath(s.keyDir),
		runespace.WithKeyID("harness"),
		runespace.WithKeyDim(s.dim),
	}
	if s.opts.flatMode != "" {
		opts = append(opts, runespace.WithFlatMode(s.opts.flatMode))
	}
	return opts
}

// client returns a ready client bound to this instance's key set, closed on test
// cleanup. nprobe is server-side config (cluster.nprobe in the YAML), so the client
// takes no probe option — the server selects the probed clusters from the query.
func (s *serverInst) client(t *testing.T) *runespace.Client {
	t.Helper()
	c, err := runespace.Dial(s.addr, runespace.WithInsecure())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	keys, err := runespace.OpenKeys(s.keyOpts()...)
	if err != nil {
		t.Fatalf("OpenKeys: %v", err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	c.UseKeys(keys)
	return c
}

// exited reports whether the process has terminated (non-blocking).
func (s *serverInst) exited() bool {
	if s.done == nil {
		return true
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// signalAndReap delivers sig to the whole process group and waits for exit,
// escalating to SIGKILL if the process ignores it past the grace window.
func (s *serverInst) signalAndReap(sig syscall.Signal, grace time.Duration) {
	if s.cmd == nil || s.exited() {
		s.cmd = nil
		return
	}
	_ = syscall.Kill(-s.cmd.Process.Pid, sig)
	select {
	case <-s.done:
	case <-time.After(grace):
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		<-s.done
	}
	s.cmd = nil
}

// kill is an abrupt crash (SIGKILL, no drain).
func (s *serverInst) kill() { s.signalAndReap(syscall.SIGKILL, 0) }

// term is a graceful shutdown (SIGTERM, drain within the grace window).
func (s *serverInst) term() { s.signalAndReap(syscall.SIGTERM, 15*time.Second) }

// restart simulates a crash-recovery cycle: SIGKILL, then boot the same PV again.
func (s *serverInst) restart() {
	s.kill()
	s.start()
}

// stop is the t.Cleanup hook: kill a still-running process so no orphan survives.
func (s *serverInst) stop() {
	if s.cmd != nil && !s.exited() {
		s.signalAndReap(syscall.SIGKILL, 0)
	}
}

// logTail returns the last ~4 KiB of the current server log for failure messages.
func (s *serverInst) logTail() string {
	path := filepath.Join(s.logDir(), fmt.Sprintf("server.%d.log", s.restarts-1))
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	const max = 4 << 10
	if len(b) > max {
		b = b[len(b)-max:]
	}
	return string(b)
}

// --- PV readers (shallow: counts/existence only, no server-internal imports) ----

// pvClusterCells counts the immutable MM cell files (<cluster>/cells/<id>, named by
// numeric id, no extension).
func (s *serverInst) pvClusterCells() int { return countCells(filepath.Join(s.clusterDir(), "cells")) }

// pvSingles counts the durable single SoT files (<cluster>/singles/<id>.single).
func (s *serverInst) pvSingles() int {
	return countSuffix(filepath.Join(s.clusterDir(), "singles"), ".single")
}

// pvStagedFlat counts the staged flat cell files (<flat>/cells/<id>) — the rebalance
// fold backlog (the active memtable lives in the WAL, not here).
func (s *serverInst) pvStagedFlat() int { return countCells(filepath.Join(s.flatDir(), "cells")) }

// countCells counts sealed cell files in a cellstore dir: regular files named by
// numeric id (no extension), excluding the <id>.tmp written mid-rename. A missing
// dir is 0 (the server creates these subdirs lazily).
func countCells(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		nm := e.Name()
		if e.IsDir() || (len(nm) >= 4 && nm[len(nm)-4:] == ".tmp") {
			continue
		}
		n++
	}
	return n
}

// countSuffix counts regular files under dir whose name ends in suffix; a missing
// dir is 0.
func countSuffix(dir, suffix string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > len(suffix) && e.Name()[len(e.Name())-len(suffix):] == suffix {
			n++
		}
	}
	return n
}

// freePort grabs an ephemeral port and releases it for the server to bind.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestHarness_BootRegisterInsertSearchRestart is the W1 smoke: it proves the
// harness can stand up a real server, open the data plane, round-trip an insert and
// search through the SDK (real FHE), persist the singles SoT, and — after an abrupt
// SIGKILL — boot the same PV back to ready with the data intact. A small
// stage_threshold also forces a flat-cell rotation so the staged backlog is
// observable on disk (the rebalance trigger plumbing), all at tiny scale.
func TestHarness_BootRegisterInsertSearchRestart(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8, stageThreshold: 16})
	s.start()
	s.register()
	s.waitReady(10 * time.Minute) // dim-sized key load can be slow

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c := s.client(t)

	const n = 40
	rng := rand.New(rand.NewSource(1))
	ids := make([]string, n)
	vecs := make([][]float32, n)
	for i := range ids {
		vecs[i] = genVec(s.dim, rng)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"i":%d}`, i))
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids[i] = id
	}

	hits, err := c.Search(ctx, vecs[0], 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 || hits[0].ID != ids[0] {
		t.Fatalf("pre-restart top = %s; want id %s", summarizeHits(hits), ids[0])
	}

	// PV: singles are the durable SoT (one per item); flat rotated at threshold 16
	// so at least one staged cell exists on disk.
	if got := s.pvSingles(); got < n {
		t.Errorf("singles on disk = %d; want >= %d", got, n)
	}
	if got := s.pvStagedFlat(); got < 1 {
		t.Errorf("staged flat cells = %d; want >= 1 (threshold 16, %d rows)", got, n)
	}
	t.Logf("pre-restart: singles=%d stagedFlat=%d clusterCells=%d", s.pvSingles(), s.pvStagedFlat(), s.pvClusterCells())

	// Crash and recover on the same PV: keys reload (auto-ready), data survives.
	s.restart()
	s.waitReady(10 * time.Minute)
	c2 := s.client(t)
	hits, err = c2.Search(ctx, vecs[0], 10)
	if err != nil {
		t.Fatalf("post-restart search: %v", err)
	}
	if len(hits) == 0 || hits[0].ID != ids[0] {
		t.Fatalf("post-restart top = %s; want id %s (data lost across restart?)", summarizeHits(hits), ids[0])
	}
	if got := s.pvSingles(); got < n {
		t.Errorf("post-restart singles = %d; want >= %d (SoT lost?)", got, n)
	}
}
