//go:build e2e

// Package e2e is the black-box integration suite for the RuneSpace SDK against a
// live instance. The whole suite is skipped unless RUNESPACE_ADDR points at a
// reachable server, so a missing endpoint never red-flags CI; the e2e build tag
// also keeps it out of `go build ./...`.
//
// One key set is generated and registered ONCE in TestMain (the "vault" role)
// and shared by every test, mirroring the deployment model: a single client
// registers the eval keys, and every other client binds the same key set with
// UseKeys. The target server must therefore start UNREGISTERED — set
// RUNESPACE_ADDR to a fresh instance.
//
//	RUNESPACE_ADDR=127.0.0.1:51024 RUNESPACE_INSECURE=1 RUNESPACE_DIM=1024 \
//	  go test -tags e2e ./tests/e2e/ -v
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// shared holds the one key set registered in TestMain and reused by every test.
var shared struct {
	addr    string
	dim     int
	keyOpts []runespace.KeysOption
	ready   bool // RUNESPACE_ADDR set, keys generated + registered
}

func TestMain(m *testing.M) {
	addr := os.Getenv("RUNESPACE_ADDR")
	if addr != "" {
		if err := setupShared(addr); err != nil {
			fmt.Fprintf(os.Stderr, "e2e setup failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// setupShared generates one key set and registers it with the target instance
// (the vault role). Every test then binds this same set with UseKeys.
func setupShared(addr string) error {
	dim := envDim()
	dir, err := os.MkdirTemp("", "e2e-keys-*")
	if err != nil {
		return err
	}
	keyOpts := []runespace.KeysOption{
		runespace.WithKeyPath(dir),
		runespace.WithKeyID("e2e"),
		runespace.WithKeyDim(dim),
	}
	if err := runespace.GenerateKeys(keyOpts...); err != nil {
		return fmt.Errorf("GenerateKeys: %w", err)
	}
	c, err := runespace.Dial(addr, dialOpts()...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	keys, err := runespace.OpenKeys(keyOpts...)
	if err != nil {
		return fmt.Errorf("OpenKeys: %w", err)
	}
	defer keys.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := c.RegisterKeys(ctx, keys); err != nil {
		return fmt.Errorf("RegisterKeys (instance must start unregistered): %w", err)
	}
	shared.addr, shared.dim, shared.keyOpts, shared.ready = addr, dim, keyOpts, true
	return nil
}

// envDim is the dimension the target instance was configured for (RUNESPACE_DIM,
// default 1024).
func envDim() int {
	if s := os.Getenv("RUNESPACE_DIM"); s != "" {
		if d, err := strconv.Atoi(s); err == nil && d > 0 {
			return d
		}
	}
	return 1024
}

func dialOpts() []runespace.ClientOption {
	var opts []runespace.ClientOption
	if tok := os.Getenv("RUNESPACE_TOKEN"); tok != "" {
		opts = append(opts, runespace.WithAccessToken(tok))
	}
	if os.Getenv("RUNESPACE_INSECURE") != "" {
		opts = append(opts, runespace.WithInsecure())
	}
	return opts
}

// e2eClient dials the shared instance and binds the shared key set with UseKeys
// (no re-register). Skips the test when no server is configured.
func e2eClient(t *testing.T) *runespace.Client {
	t.Helper()
	if !shared.ready {
		t.Skip("RUNESPACE_ADDR not set; skipping RuneSpace e2e")
	}
	c, err := runespace.Dial(shared.addr, dialOpts()...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	keys, err := runespace.OpenKeys(shared.keyOpts...)
	if err != nil {
		t.Fatalf("OpenKeys: %v", err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	c.UseKeys(keys)
	return c
}

// TestE2E_Info verifies the transport/auth handshake, the engine self-check, and
// that the shared keys registered in TestMain are reported by GetInfo.
func TestE2E_Info(t *testing.T) {
	c := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := c.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	t.Logf("engine: version=%q status=%q probeDim=%d ready=%v registered_keys=%d",
		info.Version, info.EngineStatus, info.EngineProbeDim, info.Ready, len(info.RegisteredKeys))
	if info.EngineStatus != "ok" {
		t.Errorf("engine status = %q, want %q", info.EngineStatus, "ok")
	}
	if !info.Ready {
		t.Errorf("ready = false; want true after TestMain registration")
	}
	if len(info.RegisteredKeys) == 0 {
		t.Errorf("registered_keys empty; want the vault's keys")
	}
}

// TestE2E_VerifyKeys confirms the instance is serving exactly the shared key set
// (kid + params + sha256 fingerprint round-trip via GetInfo).
func TestE2E_VerifyKeys(t *testing.T) {
	c := e2eClient(t)
	keys, err := runespace.OpenKeys(shared.keyOpts...)
	if err != nil {
		t.Fatalf("OpenKeys: %v", err)
	}
	defer keys.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.VerifyKeys(ctx, keys); err != nil {
		t.Fatalf("VerifyKeys (expected match): %v", err)
	}
}

// TestE2E_VerifyKeysForeign confirms a FOREIGN key set (different kid +
// fingerprint) is rejected against the instance registered with the vault keys.
func TestE2E_VerifyKeysForeign(t *testing.T) {
	if !shared.ready {
		t.Skip("RUNESPACE_ADDR not set; skipping RuneSpace e2e")
	}
	dir := t.TempDir()
	altOpts := []runespace.KeysOption{
		runespace.WithKeyPath(dir),
		runespace.WithKeyID("foreign"),
		runespace.WithKeyDim(shared.dim),
	}
	if err := runespace.GenerateKeys(altOpts...); err != nil {
		t.Fatalf("GenerateKeys(foreign): %v", err)
	}
	alt, err := runespace.OpenKeys(altOpts...)
	if err != nil {
		t.Fatalf("OpenKeys(foreign): %v", err)
	}
	defer alt.Close()
	c, err := runespace.Dial(shared.addr, dialOpts()...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	c.UseKeys(alt)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.VerifyKeys(ctx, alt); err == nil {
		t.Fatal("VerifyKeys accepted a foreign key set; want rejection")
	} else {
		t.Logf("foreign key correctly rejected: %v", err)
	}
}

// TestE2E_InsertSearchMetadata inserts vectors with metadata and verifies a
// self-query ranks its own id first with a normalized score and intact metadata.
func TestE2E_InsertSearchMetadata(t *testing.T) {
	c := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rng := rand.New(rand.NewSource(1))
	const n = 20
	ids := make([]string, n)
	vecs := make([][]float32, n)
	for i := range ids {
		vecs[i] = genVec(shared.dim, rng)
		id, err := c.Insert(ctx, vecs[i], fmt.Sprintf(`{"idx":%d}`, i))
		if err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
		ids[i] = id
	}

	probe := n / 2
	hits, err := c.Search(ctx, vecs[probe], 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	if hits[0].ID != ids[probe] {
		t.Fatalf("top hit = %q; want %q (probe %d). hits=%+v", hits[0].ID, ids[probe], probe, hits)
	}
	if hits[0].Score < 0.9 || hits[0].Score > 1.01 {
		t.Errorf("self-match score = %.4f; want ~1.0 (normalized IP)", hits[0].Score)
	}
	var got struct {
		Idx int `json:"idx"`
	}
	if err := json.Unmarshal([]byte(hits[0].Metadata), &got); err != nil {
		t.Fatalf("top hit metadata %q not JSON: %v", hits[0].Metadata, err)
	}
	if got.Idx != probe {
		t.Errorf("top hit metadata idx = %d, want %d", got.Idx, probe)
	}
}

// TestE2E_DeleteBitsetSkip verifies a deleted id is folded out of Search results
// by the server-side dead-slot filter (the documented bitset skip).
func TestE2E_DeleteBitsetSkip(t *testing.T) {
	c := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rng := rand.New(rand.NewSource(2))
	const n = 10
	ids := make([]string, n)
	vecs := make([][]float32, n)
	for i := range ids {
		vecs[i] = genVec(shared.dim, rng)
		id, err := c.Insert(ctx, vecs[i], "")
		if err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
		ids[i] = id
	}

	probe := 1
	hits, err := c.Search(ctx, vecs[probe], n)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 || hits[0].ID != ids[probe] {
		t.Fatalf("pre-delete top hit = %+v; want id %q", hits, ids[probe])
	}
	if err := c.Delete(ctx, ids[probe]); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	hits, err = c.Search(ctx, vecs[probe], n)
	if err != nil {
		t.Fatalf("Search after delete: %v", err)
	}
	for _, h := range hits {
		if h.ID == ids[probe] {
			t.Errorf("deleted id %q still present after delete: %+v", ids[probe], hits)
		}
	}
}

// TestE2E_MultiClient models a shared index: many clients bind the SAME
// vault-registered key set (UseKeys, no re-register) and concurrently
// insert/search/delete, checking cross-client id + metadata resolution.
func TestE2E_MultiClient(t *testing.T) {
	if !shared.ready {
		t.Skip("RUNESPACE_ADDR not set; skipping RuneSpace e2e")
	}
	const clients, per = 8, 10
	errs := make([]error, clients)
	var wg sync.WaitGroup
	for w := 0; w < clients; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			errs[w] = runClientWorker(w, per)
		}(w)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Errorf("client %d: %v", w, err)
		}
	}
}

func runClientWorker(w, per int) error {
	c, err := runespace.Dial(shared.addr, dialOpts()...)
	if err != nil {
		return err
	}
	defer c.Close()
	keys, err := runespace.OpenKeys(shared.keyOpts...)
	if err != nil {
		return err
	}
	defer keys.Close()
	c.UseKeys(keys)

	rng := rand.New(rand.NewSource(int64(100 + w)))
	ctx := context.Background()
	ids := make([]string, 0, per)
	vecs := make([][]float32, 0, per)
	for i := 0; i < per; i++ {
		v := genVec(shared.dim, rng)
		id, err := c.Insert(ctx, v, fmt.Sprintf(`{"client":%d,"i":%d}`, w, i))
		if err != nil {
			return fmt.Errorf("insert: %w", err)
		}
		ids = append(ids, id)
		vecs = append(vecs, v)
	}
	for i := range vecs {
		hits, err := c.Search(ctx, vecs[i], 10)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}
		if len(hits) == 0 || hits[0].ID != ids[i] {
			return fmt.Errorf("self-match failed for i=%d (got %+v)", i, hits)
		}
		var md struct {
			Client int `json:"client"`
		}
		_ = json.Unmarshal([]byte(hits[0].Metadata), &md)
		if md.Client != w {
			return fmt.Errorf("metadata client=%d mismatch (want %d)", md.Client, w)
		}
	}
	for i := 0; i < len(ids); i += 2 {
		if err := c.Delete(ctx, ids[i]); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
	}
	return nil
}

// TestE2E_Load pre-inserts a corpus, then drives concurrent search workers and
// logs latency percentiles + throughput. Sized via RUNESPACE_LOAD_* envs.
func TestE2E_Load(t *testing.T) {
	c := e2eClient(t)
	corpus := envInt("RUNESPACE_LOAD_CORPUS", 150)
	clients := envInt("RUNESPACE_LOAD_CLIENTS", 8)
	ops := envInt("RUNESPACE_LOAD_OPS", 30)

	rng := rand.New(rand.NewSource(7))
	corpusVecs := make([][]float32, corpus)
	insLat := make([]time.Duration, 0, corpus)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < corpus; i++ {
		corpusVecs[i] = genVec(shared.dim, rng)
		ti := time.Now()
		if _, err := c.Insert(ctx, corpusVecs[i], fmt.Sprintf(`{"i":%d}`, i)); err != nil {
			t.Fatalf("corpus insert %d: %v", i, err)
		}
		insLat = append(insLat, time.Since(ti))
	}
	logStats(t, "insert", insLat, time.Since(start))

	total := clients * ops
	lat := make([][]time.Duration, clients)
	var failed atomic.Int64
	var wg sync.WaitGroup
	start = time.Now()
	for w := 0; w < clients; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			wc, err := runespace.Dial(shared.addr, dialOpts()...)
			if err != nil {
				failed.Add(int64(ops))
				return
			}
			defer wc.Close()
			wk, err := runespace.OpenKeys(shared.keyOpts...)
			if err != nil {
				failed.Add(int64(ops))
				return
			}
			defer wk.Close()
			wc.UseKeys(wk)
			r := rand.New(rand.NewSource(int64(1000 + w)))
			out := make([]time.Duration, 0, ops)
			for i := 0; i < ops; i++ {
				q := corpusVecs[r.Intn(len(corpusVecs))]
				ti := time.Now()
				if _, err := wc.Search(context.Background(), q, 10); err != nil {
					failed.Add(1)
					continue
				}
				out = append(out, time.Since(ti))
			}
			lat[w] = out
		}(w)
	}
	wg.Wait()
	all := make([]time.Duration, 0, total)
	for _, s := range lat {
		all = append(all, s...)
	}
	logStats(t, "search", all, time.Since(start))
	if f := failed.Load(); f > 0 {
		t.Errorf("%d/%d search ops failed", f, total)
	}
}

// --- helpers ---------------------------------------------------------------

func genVec(dim int, rng *rand.Rand) []float32 {
	v := make([]float32, dim)
	var norm float64
	for i := range v {
		x := rng.NormFloat64()
		v[i] = float32(x)
		norm += x * x
	}
	norm = math.Sqrt(norm)
	if norm == 0 {
		norm = 1
	}
	for i := range v {
		v[i] = float32(float64(v[i]) / norm)
	}
	return v
}

func envInt(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func logStats(t *testing.T, label string, lat []time.Duration, wall time.Duration) {
	t.Helper()
	if len(lat) == 0 {
		t.Logf("%s: no samples", label)
		return
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	var sum time.Duration
	for _, d := range lat {
		sum += d
	}
	t.Logf("%s: n=%d qps=%.0f mean=%s p50=%s p95=%s p99=%s max=%s",
		label, len(lat), float64(len(lat))/wall.Seconds(),
		sum/time.Duration(len(lat)), pct(lat, 50), pct(lat, 95), pct(lat, 99), lat[len(lat)-1])
}

func pct(sorted []time.Duration, p float64) time.Duration {
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
