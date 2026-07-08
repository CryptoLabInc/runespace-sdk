//go:build e2e

// delete_test.go (W3): delete idempotency, client-side dimension guards, unknown
// metadata positions, and the monotonic tombstone epoch. Runs against the shared,
// key-registered instance (RUNESPACE_ADDR); the precise-reason wire matrix is in
// badpath_test.go and the tombstone-fold-after-compaction case is in tombstone_test.go.
package e2e

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	runespace "github.com/CryptoLabInc/runespace-sdk"
	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// TestE2E_DeleteIdempotent verifies Delete is a no-op success for an unknown id and
// for an already-deleted id (the ack-loss retry path).
func TestE2E_DeleteIdempotent(t *testing.T) {
	c := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := c.Delete(ctx, uuid.NewString()); err != nil {
		t.Errorf("delete unknown id: want nil (no-op), got %v", err)
	}

	id, err := c.Insert(ctx, genVec(shared.dim, rand.New(rand.NewSource(5))), "")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := c.Delete(ctx, id); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := c.Delete(ctx, id); err != nil {
		t.Errorf("second delete (idempotent): want nil, got %v", err)
	}
}

// TestE2E_DimMismatch verifies the client rejects a wrong-length vector before any
// RPC, on both Insert and Search.
func TestE2E_DimMismatch(t *testing.T) {
	c := e2eClient(t)
	ctx := context.Background()
	bad := make([]float32, shared.dim+1)
	if _, err := c.Insert(ctx, bad, ""); !errors.Is(err, runespace.ErrDimMismatch) {
		t.Errorf("Insert wrong dim: want ErrDimMismatch, got %v", err)
	}
	if _, err := c.Search(ctx, bad, 10); !errors.Is(err, runespace.ErrDimMismatch) {
		t.Errorf("Search wrong dim: want ErrDimMismatch, got %v", err)
	}
}

// TestE2E_GetMetadataUnknownPosition verifies an unresolvable (cell_id, row) yields
// a position-aligned entry with an empty id rather than an error or a dropped slot.
func TestE2E_GetMetadataUnknownPosition(t *testing.T) {
	cl, ctx := rawClient(t)
	resp, err := cl.GetMetadata(ctx, &pb.GetMetadataRequest{
		RmpRows: []*pb.CellRow{{CellId: 4_000_000_000, Row: 999999}},
		MmRows:  []*pb.CellRow{{CellId: 4_000_000_001, Row: 888888}},
	})
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if got := resp.GetRmpEntries(); len(got) != 1 || got[0].GetId() != "" {
		t.Errorf("unknown rmp position: want exactly one empty-id entry, got %+v", got)
	}
	if got := resp.GetMmEntries(); len(got) != 1 || got[0].GetId() != "" {
		t.Errorf("unknown mm position: want exactly one empty-id entry, got %+v", got)
	}
}

// TestE2E_TombEpochMonotonic verifies the search-result tombstone epoch never goes
// backwards and advances after a delete (so a racing delete can only over-exclude,
// never leak). It reads tomb_epoch via the raw client (the SDK hides it).
func TestE2E_TombEpochMonotonic(t *testing.T) {
	cl, ctx := rawClient(t)
	sdk := e2eClient(t)

	vec := genVec(shared.dim, rand.New(rand.NewSource(8))) // already unit-normalized
	id, err := sdk.Insert(ctx, vec, "")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	first, err := cl.Search(ctx, &pb.SearchRequest{Query: vec})
	if err != nil {
		t.Fatalf("first search: %v", err)
	}
	e1 := first.GetTombEpoch()

	if err := sdk.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	second, err := cl.Search(ctx, &pb.SearchRequest{Query: vec})
	if err != nil {
		t.Fatalf("second search: %v", err)
	}
	e2 := second.GetTombEpoch()

	// Epoch is a global monotonic counter, so a delete (here, plus any concurrent
	// ones on the shared instance) only ever raises it.
	if e2 <= e1 {
		t.Errorf("tomb_epoch did not advance after delete: %d -> %d (want strictly greater)", e1, e2)
	}
}
