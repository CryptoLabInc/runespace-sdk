//go:build e2e

// badpath_test.go: the wire-contract rejection matrix. The SDK's high-level
// Insert/Search/Delete sanitize inputs client-side, so to exercise the SERVER's
// validation (and its machine-readable ErrorReason details) these tests speak the
// raw pb client directly against the shared, key-registered instance
// (RUNESPACE_ADDR). They assert the (gRPC code, ErrorReason) pair, not just failure.
//
// Cases that need server STATE rather than a bad request — boot-unregistered
// gating, the RegisterKeysStream integrity matrix, rotation-unsupported — need a
// fresh instance and live in the process-harness suite (harness_test.go).
package e2e

import (
	"context"
	"math/rand"
	"os"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	runespace "github.com/CryptoLabInc/runespace-sdk"
	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// dummyItem is a non-empty placeholder ciphertext. The server rejects bad-path
// inserts on wire shape / plaintext routing BEFORE it would ever decrypt, so these
// bytes never need to be real FHE — and a rejected insert stores nothing.
var dummyItem = []byte{0x01}

// rawClient dials the shared instance and returns the low-level pb client plus a
// context carrying the bearer token (if any). Skips when no server is configured.
// Assumes a local insecure endpoint (the e2e convention); a TLS target would need
// real transport credentials here.
func rawClient(t *testing.T) (pb.RuneSpaceServiceClient, context.Context) {
	t.Helper()
	if !shared.ready {
		t.Skip("RUNESPACE_ADDR not set; skipping RuneSpace e2e")
	}
	conn, err := grpc.NewClient(shared.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Search returns large FHE result blobs; raise the recv limit past the
		// 4 MiB gRPC default, matching the server's send limit.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256<<20)))
	if err != nil {
		t.Fatalf("dial raw: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx := context.Background()
	if tok := os.Getenv("RUNESPACE_TOKEN"); tok != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
	}
	return pb.NewRuneSpaceServiceClient(conn), ctx
}

// statusReason extracts the gRPC code and the runespace ErrorReason (from the
// google.rpc.ErrorInfo detail) from an RPC error; reason is "" when absent.
func statusReason(err error) (codes.Code, string) {
	st, ok := status.FromError(err)
	if !ok {
		return codes.Unknown, ""
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return st.Code(), ei.GetReason()
		}
	}
	return st.Code(), ""
}

// wantReason asserts an RPC failed with exactly the given code and ErrorReason.
func wantReason(t *testing.T, name string, err error, code codes.Code, reason string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: want error %s/%s, got success", name, code, reason)
		return
	}
	c, r := statusReason(err)
	if c != code || r != reason {
		t.Errorf("%s: got %s/%q, want %s/%q (err=%v)", name, c, r, code, reason, err)
	}
}

// TestE2E_InsertBadPath covers the handler's wire-shape validation: each rejected
// insert maps to its own ErrorReason and nothing is stored.
func TestE2E_InsertBadPath(t *testing.T) {
	cl, ctx := rawClient(t)
	good := uuid.NewString()
	cases := []struct {
		name   string
		req    *pb.InsertRequest
		code   codes.Code
		reason string
	}{
		{"non-uuid id", &pb.InsertRequest{Id: "not-a-uuid", RmpItem: &pb.RMPItem{Item: dummyItem}, MmItem: &pb.MMItem{Item: dummyItem}},
			codes.InvalidArgument, "ERROR_REASON_INVALID_ID"},
		{"missing rmp_item", &pb.InsertRequest{Id: good},
			codes.InvalidArgument, "ERROR_REASON_MISSING_RMP_ITEM"},
		{"missing mm_item", &pb.InsertRequest{Id: good, RmpItem: &pb.RMPItem{Item: dummyItem}},
			codes.InvalidArgument, "ERROR_REASON_MISSING_MM_ITEM"},
		{"invalid metadata json", &pb.InsertRequest{Id: good, RmpItem: &pb.RMPItem{Item: dummyItem}, MmItem: &pb.MMItem{Item: dummyItem}, Metadata: "{not json"},
			codes.InvalidArgument, "ERROR_REASON_INVALID_METADATA_JSON"},
	}
	for _, tc := range cases {
		_, err := cl.Insert(ctx, tc.req)
		wantReason(t, tc.name, err, tc.code, tc.reason)
	}
}

// TestE2E_InsertRoutingBadPath covers the engine's plaintext cluster-routing
// validation (checked before any storage). Requires a centroid set on the
// instance; skips otherwise.
func TestE2E_InsertRoutingBadPath(t *testing.T) {
	cl, ctx := rawClient(t)
	d, err := drainCentroids(cl, ctx)
	if err != nil {
		t.Fatalf("GetCentroids: %v", err)
	}
	if d.version == "" {
		t.Skip("instance has no centroid set; routing bad-path N/A")
	}
	nlist := uint32(len(d.centroids))
	ver := d.version

	// Correct version + out-of-range cluster_id ⇒ INVALID_CLUSTER_ID (version is
	// checked first, so it must be correct to isolate this reason).
	_, err = cl.Insert(ctx, &pb.InsertRequest{
		Id:      uuid.NewString(),
		RmpItem: &pb.RMPItem{Item: dummyItem},
		MmItem:  &pb.MMItem{Item: dummyItem, ClusterId: nlist, CentroidSetVersion: ver},
	})
	wantReason(t, "cluster_id>=nlist", err, codes.InvalidArgument, "ERROR_REASON_INVALID_CLUSTER_ID")

	// Wrong version ⇒ CENTROID_VERSION_MISMATCH.
	_, err = cl.Insert(ctx, &pb.InsertRequest{
		Id:      uuid.NewString(),
		RmpItem: &pb.RMPItem{Item: dummyItem},
		MmItem:  &pb.MMItem{Item: dummyItem, ClusterId: 0, CentroidSetVersion: ver + "-wrong"},
	})
	wantReason(t, "version mismatch", err, codes.InvalidArgument, "ERROR_REASON_CENTROID_VERSION_MISMATCH")
}

// TestE2E_SearchDeleteBadPath covers the empty-input rejections on Search and Delete.
func TestE2E_SearchDeleteBadPath(t *testing.T) {
	cl, ctx := rawClient(t)
	_, err := cl.Search(ctx, &pb.SearchRequest{}) // no query
	wantReason(t, "empty query", err, codes.InvalidArgument, "ERROR_REASON_MISSING_QUERY")
	_, err = cl.Delete(ctx, &pb.DeleteRequest{Id: ""})
	wantReason(t, "empty delete id", err, codes.InvalidArgument, "ERROR_REASON_MISSING_ID")
}

// TestE2E_InsertIdempotent verifies a re-insert under the SAME client-supplied id
// is a no-op success (the ack-loss retry path), so the item resolves exactly once.
// This one uses REAL ciphertext (a stored insert must be decryptable to search), so
// it needs the shared key set and a centroid set.
func TestE2E_InsertIdempotent(t *testing.T) {
	cl, ctx := rawClient(t)
	d, err := drainCentroids(cl, ctx)
	if err != nil {
		t.Fatalf("GetCentroids: %v", err)
	}
	if d.version == "" {
		t.Skip("instance has no centroid set; clustered insert N/A")
	}
	keys, err := runespace.OpenKeys(shared.keyOpts...)
	if err != nil {
		t.Fatalf("OpenKeys: %v", err)
	}
	defer keys.Close()

	vec := genVec(shared.dim, rand.New(rand.NewSource(99)))
	rmp, err := keys.EncryptFlat(vec)
	if err != nil {
		t.Fatalf("EncryptFlat: %v", err)
	}
	mm, err := keys.EncryptClustered(vec)
	if err != nil {
		t.Fatalf("EncryptClustered: %v", err)
	}
	id := uuid.NewString()
	req := &pb.InsertRequest{
		Id:      id,
		RmpItem: &pb.RMPItem{Item: rmp},
		// cluster_id 0 is a valid in-range assignment; the server trusts the client's
		// plaintext routing (it only range/version-checks it), so this is accepted.
		MmItem: &pb.MMItem{Item: mm, ClusterId: 0, CentroidSetVersion: d.version},
	}
	if _, err := cl.Insert(ctx, req); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := cl.Insert(ctx, req); err != nil {
		t.Fatalf("re-insert with same id must be an idempotent no-op, got: %v", err)
	}

	// The item resolves exactly once (no duplicate from the re-insert).
	c := e2eClient(t)
	hits, err := c.Search(ctx, vec, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	n := 0
	for _, h := range hits {
		if h.ID == id {
			n++
		}
	}
	if n != 1 {
		t.Errorf("idempotent insert: id present %d times in results, want 1 (%s)", n, summarizeHits(hits))
	}
}
