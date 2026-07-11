package runespace

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func validItem() PreEncryptedItem {
	return PreEncryptedItem{
		ID:                 "11111111-2222-3333-4444-555555555555",
		RMPBlob:            []byte{1, 2, 3},
		MMBlob:             []byte{4, 5, 6},
		ClusterID:          7,
		CentroidSetVersion: "abc123",
		Metadata:           `{"a":"x","c":"y"}`,
	}
}

func TestPreEncryptedItemValidate(t *testing.T) {
	if err := validItem().validate(); err != nil {
		t.Fatalf("valid item rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*PreEncryptedItem)
		wantSub string
		wantErr error
	}{
		{"missing id", func(it *PreEncryptedItem) { it.ID = "" }, "id is required", nil},
		{"missing rmp", func(it *PreEncryptedItem) { it.RMPBlob = nil }, "rmp blob is empty", nil},
		{"missing mm", func(it *PreEncryptedItem) { it.MMBlob = nil }, "mm blob is empty", nil},
		{"missing version", func(it *PreEncryptedItem) { it.CentroidSetVersion = "" }, "centroid_set_version", nil},
		{"bad metadata", func(it *PreEncryptedItem) { it.Metadata = "not-json" }, "", ErrInvalidMetadata},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			it := validItem()
			tc.mutate(&it)
			err := it.validate()
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want substring %q, got %v", tc.wantSub, err)
			}
		})
	}

	// Empty metadata is allowed (stored as "").
	it := validItem()
	it.Metadata = ""
	if err := it.validate(); err != nil {
		t.Fatalf("empty metadata rejected: %v", err)
	}
}

func TestInsertPreEncryptedClosedClient(t *testing.T) {
	c := &Client{} // no conn — closed/never dialed
	if err := c.InsertPreEncrypted(context.Background(), validItem()); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("want ErrClientClosed, got %v", err)
	}
}

func TestCentroidSetAssignPublic(t *testing.T) {
	s := &CentroidSet{
		Version: "v1",
		Dim:     2,
		Vectors: [][]float32{{1, 0}, {0, 1}},
	}
	if !s.Enabled() {
		t.Fatal("set should be enabled")
	}
	if got := s.Assign([]float32{0.9, 0.1}); got != 0 {
		t.Fatalf("assign x-axis: want 0, got %d", got)
	}
	if got := s.Assign([]float32{0.1, 0.9}); got != 1 {
		t.Fatalf("assign y-axis: want 1, got %d", got)
	}
	var disabled *CentroidSet
	if disabled.Enabled() {
		t.Fatal("nil set must be disabled")
	}
}
