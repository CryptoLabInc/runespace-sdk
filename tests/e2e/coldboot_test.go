//go:build coldboot

// coldboot_test.go: a Docker-driven COLD BOOT profile for runespace. It measures the
// latency a caller sees when a scaled-to-zero (stopped) container is woken by a request:
// the wall-clock from `docker start` until the data plane answers, plus the first
// (cold) query vs. the warm steady state.
//
// It owns the whole container lifecycle (create / start / stop) via the docker CLI, so
// it is isolated from the RUNESPACE_ADDR e2e suite and runs under its own build tag —
// none of the //go:build e2e files compile with -tags coldboot, so this file is the
// entire package for this build (no TestMain, no shared-key setup).
//
//	cd tests && go test -tags coldboot -run TestColdBoot ./e2e/ -v -timeout 40m
//
// Env knobs (all optional):
//
//	RUNESPACE_CB_IMAGE   docker image           (default runespace:dev)
//	RUNESPACE_CB_ROWS    rows to preload         (default 1000)
//	RUNESPACE_CB_CYCLES  stop/start cycles       (default 3)
//	RUNESPACE_CB_KEYDIR  host client-key dir     (default $TMPDIR/rs-coldboot-keys, reused)
//	RUNESPACE_CB_CONFIG  host path to the container config yaml (required)
//	RUNESPACE_CB_PORT    host port               (default 51024)
//	RUNESPACE_CB_WARM    warm searches per cycle (default 20)
package e2e

import (
	"bytes"
	"context"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

const (
	cbName      = "rs-coldboot"
	cbVol       = "rs-coldboot-data"
	cbInnerPort = "51024"
	cbKeyID     = "coldboot"
)

func cbEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func cbEnvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// docker runs a docker subcommand, returning combined output. fatal on error.
func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := dockerTry(args...)
	if err != nil {
		t.Fatalf("docker %v: %v\n%s", args, err, out)
	}
	return out
}

func dockerTry(args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

func cbGenVec(dim int, rng *rand.Rand) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rng.Float32()*2 - 1
	}
	return v
}

func pctl(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(math.Ceil(p/100*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// dialReady dials fresh and calls Info; returns (listening, ready, err). A fresh dial
// each poll so we detect the port coming up. listening = the RPC answered at all.
func dialReady(addr string) (listening, ready bool) {
	c, err := runespace.Dial(addr, runespace.WithInsecure())
	if err != nil {
		return false, false
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	info, err := c.Info(ctx)
	if err != nil {
		return false, false
	}
	return true, info.Ready
}

func TestColdBoot(t *testing.T) {
	cfg := os.Getenv("RUNESPACE_CB_CONFIG")
	if cfg == "" {
		t.Fatal("RUNESPACE_CB_CONFIG (host path to the container config yaml) is required")
	}
	if _, err := os.Stat(cfg); err != nil {
		t.Fatalf("RUNESPACE_CB_CONFIG %q: %v", cfg, err)
	}
	image := cbEnv("RUNESPACE_CB_IMAGE", "runespace:dev")
	rows := cbEnvInt("RUNESPACE_CB_ROWS", 1000)
	cycles := cbEnvInt("RUNESPACE_CB_CYCLES", 3)
	warmN := cbEnvInt("RUNESPACE_CB_WARM", 20)
	port := cbEnv("RUNESPACE_CB_PORT", "51024")
	keyDir := cbEnv("RUNESPACE_CB_KEYDIR", "")
	if keyDir == "" {
		keyDir = os.TempDir() + "/rs-coldboot-keys"
	}
	addr := "127.0.0.1:" + port
	dim := 1024

	t.Logf("=== cold-boot profile: image=%s rows=%d cycles=%d warm=%d keydir=%s ===",
		image, rows, cycles, warmN, keyDir)

	// ---- clean slate: remove any prior container + volume, recreate volume ----
	_, _ = dockerTry("rm", "-f", cbName)
	_, _ = dockerTry("volume", "rm", cbVol)
	docker(t, "volume", "create", cbVol)
	t.Cleanup(func() { _, _ = dockerTry("rm", "-f", cbName) })

	// ---- create + start the container (run as root so uid can write the named volume) ----
	docker(t, "create", "--name", cbName, "--user", "0:0",
		"-p", port+":"+cbInnerPort, "-v", cbVol+":/data", image)
	docker(t, "cp", cfg, cbName+":/etc/runespace/runespace.yaml")
	docker(t, "start", cbName)

	// wait for the port to answer (unregistered is fine here)
	waitFor(t, 60*time.Second, func() bool { l, _ := dialReady(addr); return l })

	// ---- keys: generate once (reused across runs), register with THIS container ----
	keyOpts := []runespace.KeysOption{
		runespace.WithKeyPath(keyDir),
		runespace.WithKeyID(cbKeyID),
		runespace.WithKeyDim(dim),
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir keydir: %v", err)
	}
	genStart := time.Now()
	if err := runespace.GenerateKeys(keyOpts...); err != nil && err != runespace.ErrKeysAlreadyExist {
		t.Fatalf("GenerateKeys: %v", err)
	} else if err == nil {
		t.Logf("generated client keys in %s", time.Since(genStart).Round(time.Millisecond))
	} else {
		t.Logf("reusing existing client keys at %s", keyDir)
	}

	regKeys, err := runespace.OpenKeys(keyOpts...)
	if err != nil {
		t.Fatalf("OpenKeys: %v", err)
	}
	{
		c, err := runespace.Dial(addr, runespace.WithInsecure())
		if err != nil {
			t.Fatalf("dial for register: %v", err)
		}
		regStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		if err := c.RegisterKeys(ctx, regKeys); err != nil {
			cancel()
			_ = c.Close()
			t.Fatalf("RegisterKeys: %v", err)
		}
		cancel()
		_ = c.Close()
		t.Logf("registered eval keys (streamed ~848MiB MM key) in %s", time.Since(regStart).Round(time.Millisecond))
	}
	_ = regKeys.Close()
	waitFor(t, 5*time.Minute, func() bool { _, r := dialReady(addr); return r })

	// ---- preload `rows` rows (concurrent, unmeasured) ----
	loadStart := time.Now()
	preload(t, addr, keyOpts, dim, rows)
	t.Logf("preloaded %d rows in %s (%.0f rows/s)", rows,
		time.Since(loadStart).Round(time.Millisecond), float64(rows)/time.Since(loadStart).Seconds())

	// ---- warm baseline while the process is hot ----
	hot := newClient(t, addr, keyOpts)
	warmBase := searchN(t, hot, dim, 20, 12345)
	t.Logf("warm baseline (pre-stop, n=20): p50=%.1fms p95=%.1fms",
		ms(pctl(warmBase, 50)), ms(pctl(warmBase, 95)))
	_ = hot.Close()

	// =====================================================================
	// COLD BOOT CYCLES: graceful stop (scale to zero) -> start (wakeup) -> query
	// =====================================================================
	type cycleRes struct {
		listenMs, readyMs, coldMs float64
		warmP50Ms, warmP95Ms      float64
		appBootMs                 float64
	}
	var results []cycleRes

	for cyc := 1; cyc <= cycles; cyc++ {
		t.Logf("--- cycle %d/%d ---", cyc, cycles)
		docker(t, "stop", "-t", "30", cbName) // graceful SIGTERM -> drain -> flush

		logMark := time.Now().UTC().Format("2006-01-02T15:04:05")

		t0 := time.Now()
		docker(t, "start", cbName)

		// poll to listening, then to ready
		var tListen, tReady time.Duration
		waitFor(t, 120*time.Second, func() bool {
			l, r := dialReady(addr)
			if l && tListen == 0 {
				tListen = time.Since(t0)
			}
			if r {
				tReady = time.Since(t0)
				return true
			}
			return false
		})

		// first query the instant it is ready — this is the COLD request
		cold := newClient(t, addr, keyOpts)
		rng := rand.New(rand.NewSource(int64(cyc) * 777))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		tq := time.Now()
		if _, err := cold.Search(ctx, cbGenVec(dim, rng), 10); err != nil {
			cancel()
			t.Fatalf("cold search cyc %d: %v", cyc, err)
		}
		coldLat := time.Since(tq)
		cancel()

		// warm steady state
		warm := searchN(t, cold, dim, warmN, int64(cyc)*999)
		_ = cold.Close()

		// cross-check: app-internal boot time from container logs (process start -> serving)
		appBoot := appBootFromLogs(logMark)

		r := cycleRes{
			listenMs:  ms(tListen),
			readyMs:   ms(tReady),
			coldMs:    ms(coldLat),
			warmP50Ms: ms(pctl(warm, 50)),
			warmP95Ms: ms(pctl(warm, 95)),
			appBootMs: appBoot,
		}
		results = append(results, r)
		t.Logf("cycle %d: start->listen=%.0fms start->ready=%.0fms | app-boot(log)=%.0fms | COLD search=%.1fms | warm p50=%.1fms p95=%.1fms",
			cyc, r.listenMs, r.readyMs, r.appBootMs, r.coldMs, r.warmP50Ms, r.warmP95Ms)
	}

	// ---- summary ----
	t.Logf("")
	t.Logf("================= COLD BOOT SUMMARY (image=%s, rows=%d) =================", image, rows)
	t.Logf("warm baseline (hot process): p50=%.1fms p95=%.1fms", ms(pctl(warmBase, 50)), ms(pctl(warmBase, 95)))
	t.Logf("%-6s %14s %14s %14s %14s %12s", "cycle", "start->ready", "app-boot(log)", "COLD 1st req", "warm p50", "cold penalty")
	var readyVals, coldVals, appVals []float64
	for i, r := range results {
		t.Logf("%-6d %12.0fms %12.0fms %12.1fms %12.1fms %10.1fms",
			i+1, r.readyMs, r.appBootMs, r.coldMs, r.warmP50Ms, r.coldMs-r.warmP50Ms)
		readyVals = append(readyVals, r.readyMs)
		coldVals = append(coldVals, r.coldMs)
		appVals = append(appVals, r.appBootMs)
	}
	t.Logf("median: start->ready=%.0fms  app-boot(log)=%.0fms  COLD-1st-req=%.1fms",
		medf(readyVals), medf(appVals), medf(coldVals))
	t.Logf("========================================================================")
}

func medf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func newClient(t *testing.T, addr string, keyOpts []runespace.KeysOption) *runespace.Client {
	t.Helper()
	c, err := runespace.Dial(addr, runespace.WithInsecure())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	keys, err := runespace.OpenKeys(keyOpts...)
	if err != nil {
		_ = c.Close()
		t.Fatalf("OpenKeys: %v", err)
	}
	c.UseKeys(keys)
	return c
}

func searchN(t *testing.T, c *runespace.Client, dim, n int, seed int64) []time.Duration {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		ti := time.Now()
		if _, err := c.Search(ctx, cbGenVec(dim, rng), 10); err != nil {
			cancel()
			t.Fatalf("search %d: %v", i, err)
		}
		lat = append(lat, time.Since(ti))
		cancel()
	}
	return lat
}

func preload(t *testing.T, addr string, keyOpts []runespace.KeysOption, dim, target int) {
	t.Helper()
	const loaders = 8
	errCh := make(chan error, loaders)
	done := make(chan struct{}, loaders)
	for w := 0; w < loaders; w++ {
		cnt := target / loaders
		if w == loaders-1 {
			cnt = target - (target/loaders)*(loaders-1)
		}
		go func(w, cnt int) {
			c, err := runespace.Dial(addr, runespace.WithInsecure())
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
			keys, err := runespace.OpenKeys(keyOpts...)
			if err != nil {
				errCh <- err
				return
			}
			defer keys.Close()
			c.UseKeys(keys)
			rng := rand.New(rand.NewSource(int64(1_000_000 * (w + 1))))
			for i := 0; i < cnt; i++ {
				if _, err := c.Insert(context.Background(), cbGenVec(dim, rng), ""); err != nil {
					errCh <- err
					return
				}
			}
			done <- struct{}{}
		}(w, cnt)
	}
	for i := 0; i < loaders; i++ {
		select {
		case err := <-errCh:
			t.Fatalf("preload: %v", err)
		case <-done:
		}
	}
}

// appBootFromLogs parses the container's JSON logs written since `sinceRFC3339` and
// returns the ms between the earliest log line and the "runespace serving" line —
// the pure application boot time (excludes docker runtime + container start overhead).
// Returns 0 when it cannot be determined.
func appBootFromLogs(sinceRFC3339 string) float64 {
	out, err := dockerTry("logs", "--since", sinceRFC3339, cbName)
	if err != nil {
		return 0
	}
	var first, serving time.Time
	for _, line := range bytes.Split([]byte(out), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		ts := extractTime(line)
		if ts.IsZero() {
			continue
		}
		if first.IsZero() {
			first = ts
		}
		if bytes.Contains(line, []byte("runespace serving")) {
			serving = ts
		}
	}
	if first.IsZero() || serving.IsZero() {
		return 0
	}
	return float64(serving.Sub(first).Microseconds()) / 1000
}

// extractTime pulls the RFC3339 "time" field out of a slog JSON line.
func extractTime(line []byte) time.Time {
	key := []byte(`"time":"`)
	i := bytes.Index(line, key)
	if i < 0 {
		return time.Time{}
	}
	rest := line[i+len(key):]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, string(rest[:j]))
	if err != nil {
		return time.Time{}
	}
	return ts
}
