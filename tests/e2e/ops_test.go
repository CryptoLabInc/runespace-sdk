//go:build e2e

// ops_test.go (W7): operational / transport surface — gRPC health serving status,
// the GetCentroids server stream (the set transfers as batched frames, no single
// oversized message), and a config-validation boot failure. The server enforces no
// auth (the bearer token is for an upstream gateway, not validated here), so there
// is no auth-rejection case.
// Keepalive survival of a minutes-long quiet search is left to manual observation
// (it can't be forced deterministically without a slow lazy assembly).
package e2e

import (
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// TestHarness_HealthServing: a freshly started instance reports SERVING on the
// standard grpc.health.v1 service (same port, no admin socket). No key registration
// is needed — health is independent of the data plane being open.
func TestHarness_HealthServing(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8})
	s.start()
	if got := s.health(t); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("health status = %v; want SERVING", got)
	}
}

// TestHarness_ConfigValidationFails: an invalid config (nprobe 0 with a centroid set
// configured) must fail at boot rather than start serving.
func TestHarness_ConfigValidationFails(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 0}) // writeConfig emits nprobe: 0 + a centroid path
	s.startExpectingFailure(t, 30*time.Second)
}

// TestE2E_GetCentroidsStream: GetCentroids streams the full set (header then
// id-ordered batches) and the client reassembles nlist*dim floats without a
// single oversized message. Runs against the shared instance.
func TestE2E_GetCentroidsStream(t *testing.T) {
	cl, ctx := rawClient(t)
	d, err := drainCentroids(cl, ctx)
	if err != nil {
		t.Fatalf("GetCentroids: %v", err)
	}
	if d.version == "" {
		t.Skip("instance has no centroid set")
	}
	if n := len(d.centroids); n == 0 {
		t.Errorf("GetCentroids returned %d centroids; want > 0", n)
	}
	if int(d.dim) != shared.dim {
		t.Errorf("centroid dim = %d; want %d", d.dim, shared.dim)
	}
}
