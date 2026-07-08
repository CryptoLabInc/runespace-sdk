//go:build e2e

// harness_util_test.go: helpers on serverInst used by the rebalance / crash /
// concurrency / ops / load suites — a raw pb client, centroid lookup (to route a
// burst to a chosen cluster), a generic poll, a boot-failure launch, and a health
// probe. Methods live here (Go allows a type's methods across files) so
// harness_test.go keeps a lean import set.
package e2e

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// centroidSetDump is a drained GetCentroids stream: the header fields plus the
// centroids flattened across batches, in id order.
type centroidSetDump struct {
	version, preset string
	dim             uint32
	centroids       []*pb.Centroid
}

// drainCentroids reads the whole GetCentroids server stream (header then
// id-ordered batches) into a centroidSetDump. Error-returning (not t.Fatal) so
// callers in non-test goroutines can route the error their own way.
func drainCentroids(cl pb.RuneSpaceServiceClient, ctx context.Context) (centroidSetDump, error) {
	var d centroidSetDump
	stream, err := cl.GetCentroids(ctx, &pb.GetCentroidsRequest{})
	if err != nil {
		return d, err
	}
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return d, nil
		}
		if err != nil {
			return d, err
		}
		switch p := chunk.GetPayload().(type) {
		case *pb.GetCentroidsChunk_Header:
			d.version, d.dim, d.preset = p.Header.GetVersion(), p.Header.GetDim(), p.Header.GetPreset()
		case *pb.GetCentroidsChunk_Batch:
			d.centroids = append(d.centroids, p.Batch.GetCentroids()...)
		}
	}
}

// logDir is where this instance's server.N.log files are written: the per-instance
// PV temp dir by default (cleaned up with the test), or, when RUNESPACE_HARNESS_LOGDIR
// is set, a stable per-instance subdir there so logs survive for inspection.
func (s *serverInst) logDir() string {
	if base := os.Getenv("RUNESPACE_HARNESS_LOGDIR"); base != "" {
		d := filepath.Join(base, filepath.Base(s.dir))
		_ = os.MkdirAll(d, 0o755)
		return d
	}
	return s.dir
}

// rawClient returns a low-level pb client bound to this instance (insecure, local;
// the server enforces no auth). The conn closes on test cleanup.
func (s *serverInst) rawClient(t *testing.T) (pb.RuneSpaceServiceClient, context.Context) {
	t.Helper()
	conn, err := grpc.NewClient(s.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Search returns large FHE result blobs — raise the recv limit past the
		// 4 MiB gRPC default to match the server's send limit.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256<<20)))
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewRuneSpaceServiceClient(conn), context.Background()
}

// centroidVec returns centroid id's vector, fetching and caching the whole set on
// first use. Skips the test if the instance has no centroid set.
func (s *serverInst) centroidVec(t *testing.T, id int) []float32 {
	t.Helper()
	if s.centVecs == nil {
		cl, ctx := s.rawClient(t)
		d, err := drainCentroids(cl, ctx)
		if err != nil {
			t.Fatalf("GetCentroids: %v", err)
		}
		if d.version == "" {
			t.Skip("instance has no centroid set; rebalance/route tests N/A")
		}
		vecs := make([][]float32, len(d.centroids))
		for i, c := range d.centroids {
			vecs[i] = c.GetVec()
		}
		s.centVecs, s.centVersion = vecs, d.version
	}
	if id < 0 || id >= len(s.centVecs) {
		t.Fatalf("centroid id %d out of range (nlist=%d)", id, len(s.centVecs))
	}
	return s.centVecs[id]
}

// waitFor polls pred until it holds or timeout elapses (fatal on timeout / if the
// process dies meanwhile).
func (s *serverInst) waitFor(t *testing.T, desc string, timeout time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		if s.exited() {
			t.Fatalf("server exited while waiting for %s (err=%v); log:\n%s", desc, s.waitErr, s.logTail())
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, desc)
}

// startExpectingFailure launches the server and asserts it EXITS non-zero within
// timeout (config-validation / boot-failure tests); it does not poll for listening.
func (s *serverInst) startExpectingFailure(t *testing.T, timeout time.Duration) {
	t.Helper()
	logf, err := os.Create(filepath.Join(s.logDir(), fmt.Sprintf("server.%d.log", s.restarts)))
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	cmd := exec.Command(s.bin, "--config", s.cfgPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		t.Fatalf("start server: %v", err)
	}
	s.cmd = cmd
	s.restarts++
	done := make(chan struct{})
	s.done = done
	go func() { s.waitErr = cmd.Wait(); _ = logf.Close(); close(done) }()
	select {
	case <-done:
		s.cmd = nil
		if s.waitErr == nil {
			t.Fatalf("server exited 0; expected a boot failure. log:\n%s", s.logTail())
		}
	case <-time.After(timeout):
		t.Fatalf("server still running after %s; expected a boot failure", timeout)
	}
}

// health returns the grpc.health.v1 serving status for the default service.
func (s *serverInst) health(t *testing.T) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()
	conn, err := grpc.NewClient(s.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("health dial: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	return resp.GetStatus()
}

// nearCentroid returns a unit vector close to base (a centroid), so it routes to
// that centroid by nearest inner product. jitter sets how tight the cluster is.
func nearCentroid(base []float32, rng *rand.Rand, jitter float64) []float32 {
	v := make([]float32, len(base))
	var norm float64
	for i := range v {
		x := float64(base[i]) + rng.NormFloat64()*jitter
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
