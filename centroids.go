package runespace

import (
	"context"
	"fmt"
)

// CentroidSet is a public snapshot of the server's immutable IVF centroid set.
// The Rune stack uses it for relay: the Console fetches it here and re-serves it
// to clients (rune-mcp → runed) that never dial runespace directly, so the
// embedding side can compute the plaintext cluster assignment for inserts.
//
// Version is the set's content hash (sha256); an empty Version means the
// instance has no clustered tier configured. Vectors[i] is cluster i's
// centroid; len(Vectors) == nlist.
type CentroidSet struct {
	Version string
	Dim     int
	// Preset is the evi preset the set was trained for (e.g. "IP1"). It is a
	// Version-hash ingredient, so relay consumers (runed) need it to recompute
	// and verify the content hash. Empty when the server predates the field.
	Preset  string
	Vectors [][]float32
}

// Enabled reports whether the server has a usable clustered tier. When false,
// inserts are impossible (the clustered tier is mandatory) — treat it as a
// deployment error, not a mode.
func (s *CentroidSet) Enabled() bool {
	return s != nil && s.Version != "" && len(s.Vectors) > 0
}

// Assign returns the cluster id whose centroid has the highest inner product
// with vec — the same plaintext hard single assignment Insert uses. vec must
// be l2-normalized (embeddings from the Rune embedder already are). Exposed so
// relay consumers can route without re-implementing the metric; ties resolve
// to the lowest id.
func (s *CentroidSet) Assign(vec []float32) uint32 {
	cs := centroidSet{version: s.Version, dim: s.Dim, vectors: s.Vectors}
	return cs.assign(vec)
}

// Centroids fetches the server's centroid set once and returns it. It shares
// the client's internal cache with Insert routing, so calling both costs one
// stream. Unlike the internal path this is exported for the Console relay; a
// server without a clustered tier yields a set with Enabled() == false.
func (c *Client) Centroids(ctx context.Context) (*CentroidSet, error) {
	cs, err := c.centroidSetCached(ctx)
	if err != nil {
		return nil, fmt.Errorf("runespace: centroids: %w", err)
	}
	return &CentroidSet{Version: cs.version, Dim: cs.dim, Preset: cs.preset, Vectors: cs.vectors}, nil
}
