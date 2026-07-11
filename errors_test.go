package runespace

import (
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func mismatchStatusErr(t *testing.T, reason string) error {
	t.Helper()
	st, err := status.New(codes.InvalidArgument, "centroid_set_version does not match the instance's centroid set").
		WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "runespace.v1"})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	return st.Err()
}

func TestIsCentroidVersionMismatch(t *testing.T) {
	if !isCentroidVersionMismatch(mismatchStatusErr(t, centroidMismatchReason)) {
		t.Fatal("mismatch reason not detected")
	}
	if isCentroidVersionMismatch(mismatchStatusErr(t, "ERROR_REASON_INVALID_CLUSTER_ID")) {
		t.Fatal("unrelated reason detected as mismatch")
	}
	if isCentroidVersionMismatch(errors.New("plain")) {
		// status.FromError wraps unknown errors as codes.Unknown with no details.
		t.Fatal("plain error detected as mismatch")
	}
	if isCentroidVersionMismatch(status.Error(codes.InvalidArgument, "no details")) {
		t.Fatal("detail-less status detected as mismatch")
	}
}

func TestInvalidateCentroidCache(t *testing.T) {
	c := &Client{centroids: &centroidSet{version: "v1"}, centroidsLoaded: true}
	c.InvalidateCentroidCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.centroidsLoaded || c.centroids != nil {
		t.Fatalf("cache not cleared: loaded=%v set=%v", c.centroidsLoaded, c.centroids)
	}
}
