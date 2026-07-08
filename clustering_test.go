package runespace

import (
	"io"
	"testing"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// fakeCentroidStream replays a fixed sequence of GetCentroids chunks, then io.EOF.
type fakeCentroidStream struct {
	chunks []*pb.GetCentroidsChunk
	i      int
}

func (f *fakeCentroidStream) Recv() (*pb.GetCentroidsChunk, error) {
	if f.i >= len(f.chunks) {
		return nil, io.EOF
	}
	c := f.chunks[f.i]
	f.i++
	return c, nil
}

func headerChunk(version string, dim, nlist uint32, preset string) *pb.GetCentroidsChunk {
	return &pb.GetCentroidsChunk{Payload: &pb.GetCentroidsChunk_Header{
		Header: &pb.CentroidSetHeader{Version: version, Dim: dim, Preset: preset, Nlist: nlist},
	}}
}

func batchChunk(centroids ...*pb.Centroid) *pb.GetCentroidsChunk {
	return &pb.GetCentroidsChunk{Payload: &pb.GetCentroidsChunk_Batch{
		Batch: &pb.CentroidBatch{Centroids: centroids},
	}}
}

func TestCentroidSetEnabled(t *testing.T) {
	cases := []struct {
		name string
		cs   *centroidSet
		want bool
	}{
		{"nil", nil, false},
		{"empty version", &centroidSet{version: "", vectors: [][]float32{{1}}}, false},
		{"no vectors", &centroidSet{version: "sha256:x"}, false},
		{"populated", &centroidSet{version: "sha256:x", vectors: [][]float32{{1}}}, true},
	}
	for _, tc := range cases {
		if got := tc.cs.enabled(); got != tc.want {
			t.Errorf("%s: enabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCentroidSetAssign(t *testing.T) {
	// Three centroids in 2D: max inner product picks the cluster.
	cs := &centroidSet{
		version: "sha256:x",
		dim:     2,
		vectors: [][]float32{{1, 0}, {0, 1}, {-1, 0}},
	}
	cases := []struct {
		vec  []float32
		want uint32
	}{
		{[]float32{0.9, 0.1}, 0},
		{[]float32{0.1, 0.9}, 1},
		{[]float32{-0.8, 0.0}, 2},
	}
	for _, tc := range cases {
		if got := cs.assign(tc.vec); got != tc.want {
			t.Errorf("assign(%v) = %d, want %d", tc.vec, got, tc.want)
		}
	}
	// Ties resolve to the lowest id.
	tie := &centroidSet{version: "sha256:x", dim: 2, vectors: [][]float32{{1, 0}, {1, 0}}}
	if got := tie.assign([]float32{1, 0}); got != 0 {
		t.Errorf("tie assign = %d, want 0 (lowest id)", got)
	}
}

func TestReadCentroidSet(t *testing.T) {
	// Header then two separate batch frames — exercises appending across batches.
	stream := &fakeCentroidStream{chunks: []*pb.GetCentroidsChunk{
		headerChunk("sha256:abc", 2, 2, "IP1"),
		batchChunk(&pb.Centroid{Id: 0, Vec: []float32{1, 0}}),
		batchChunk(&pb.Centroid{Id: 1, Vec: []float32{0, 1}}),
	}}
	cs, err := readCentroidSet(stream)
	if err != nil {
		t.Fatalf("readCentroidSet: %v", err)
	}
	if cs.version != "sha256:abc" || cs.dim != 2 || len(cs.vectors) != 2 {
		t.Fatalf("read = %+v", cs)
	}
	if !cs.enabled() {
		t.Error("set with 2 centroids should be enabled")
	}

	// Header-only with an empty version → disabled clustered tier.
	empty := &fakeCentroidStream{chunks: []*pb.GetCentroidsChunk{headerChunk("", 0, 0, "")}}
	cs2, err := readCentroidSet(empty)
	if err != nil {
		t.Fatalf("readCentroidSet empty: %v", err)
	}
	if cs2.enabled() {
		t.Error("empty header should be disabled")
	}
}
