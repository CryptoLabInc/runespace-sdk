package runespace

import (
	"context"
	"fmt"
	"io"
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// FlatClusterID is the sentinel source id for the flat (RMP) tier in a Match's
// ClusterID. It is negative because the flat tier is not a cluster; clusters use
// ids 0..nlist-1.
const FlatClusterID = int32(-1)

// centroidSet is the in-memory cache of the server's immutable IVF centroid set,
// fetched once via GetCentroids and used to route inserts in plaintext (the server
// can't assign a ciphertext single). Search routing is server-side now — the server
// holds the same set and the plaintext query, so it selects the probed clusters
// itself; the client only needs this for Insert. The client never loads a centroid
// artifact itself — the server is the single source of the registered set. An empty
// version means the clustered tier is unconfigured; inserts then fail with
// ErrClusterRequired (every insert must carry an MM single).
type centroidSet struct {
	version string
	dim     int
	preset  string // evi preset the set was trained for (hash ingredient — relayed for verification)
	vectors [][]float32 // vectors[i] is cluster i's centroid; len == nlist
}

// centroidStreamReader is the subset of the GetCentroids server stream the
// assembler consumes; it lets readCentroidSet be unit-tested with a fake.
type centroidStreamReader interface {
	Recv() (*pb.GetCentroidsChunk, error)
}

// readCentroidSet assembles the cache from the GetCentroids stream: the header
// frame carries the set's version/dim (and nlist, used to preallocate), then the
// batches carry the centroids. The server sends them in id order, so appending
// in receive order keeps index i == cluster id i. An empty version (unconfigured
// tier) yields a disabled set with no vectors.
func readCentroidSet(stream centroidStreamReader) (*centroidSet, error) {
	cs := &centroidSet{}
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return cs, nil
		}
		if err != nil {
			return nil, err
		}
		switch p := chunk.GetPayload().(type) {
		case *pb.GetCentroidsChunk_Header:
			cs.version = p.Header.GetVersion()
			cs.dim = int(p.Header.GetDim())
			cs.preset = p.Header.GetPreset()
			if n := p.Header.GetNlist(); n > 0 {
				cs.vectors = make([][]float32, 0, n)
			}
		case *pb.GetCentroidsChunk_Batch:
			for _, c := range p.Batch.GetCentroids() {
				cs.vectors = append(cs.vectors, c.GetVec())
			}
		}
	}
}

// enabled reports whether the server has a usable clustered tier. When false,
// Insert fails with ErrClusterRequired and Search skips cluster probing.
func (cs *centroidSet) enabled() bool {
	return cs != nil && cs.version != "" && len(cs.vectors) > 0
}

// assign returns the cluster id whose centroid has the highest inner product with
// vec — the plaintext hard single assignment. RuneSpace is inner-product based
// (IP presets, PCMM), so "nearest" is max dot product; insert routing and search
// probing must agree on this metric. Ties resolve to the lowest id.
func (cs *centroidSet) assign(vec []float32) uint32 {
	bestID := uint32(0)
	best := math.Inf(-1)
	for i, c := range cs.vectors {
		var s float64
		for j := 0; j < len(c) && j < len(vec); j++ {
			s += float64(c[j]) * float64(vec[j])
		}
		if s > best {
			best, bestID = s, uint32(i)
		}
	}
	return bestID
}

// l2normalize returns a unit-length copy of vec. RuneSpace scores by inner product,
// so the client normalizes before sending: a unit vector makes the inner-product
// scores cosine similarities (a self-match scores ~1.0) and keeps inserts and queries
// in the same space. A zero vector has no direction and is returned unchanged.
func l2normalize(vec []float32) []float32 {
	var sum float64
	for _, v := range vec {
		sum += float64(v) * float64(v)
	}
	if sum == 0 {
		return vec
	}
	inv := float32(1 / math.Sqrt(sum))
	out := make([]float32, len(vec))
	for i, v := range vec {
		out[i] = v * inv
	}
	return out
}

// InvalidateCentroidCache drops the cached centroid set so the next
// Centroids() / insert-routing call refetches it from the server. Call it when
// the server reports a centroid version mismatch (ErrCentroidVersionMismatch)
// — the set was replaced while this client was running — so relays (the Vault)
// stop serving the stale set.
func (c *Client) InvalidateCentroidCache() {
	c.mu.Lock()
	c.centroids, c.centroidsLoaded = nil, false
	c.mu.Unlock()
}

// centroidSetCached returns the server's IVF centroid set, fetching it once via
// the GetCentroids stream and caching the result (including a disabled tier) for
// reuse. The stream is drained outside the lock; concurrent first-callers may
// each fetch, but only one caches and all converge on it. A server that predates
// GetCentroids replies Unimplemented (surfaced on the first stream read) and is
// treated as having no clustered tier.
func (c *Client) centroidSetCached(ctx context.Context) (*centroidSet, error) {
	c.mu.Lock()
	if c.centroidsLoaded {
		cs := c.centroids
		c.mu.Unlock()
		return cs, nil
	}
	c.mu.Unlock()

	var cs *centroidSet
	stream, err := c.svc.GetCentroids(ctx, &pb.GetCentroidsRequest{})
	if err == nil {
		cs, err = readCentroidSet(stream)
	}
	if err != nil {
		if status.Code(err) != codes.Unimplemented {
			return nil, fmt.Errorf("runespace: get centroids: %w", err)
		}
		cs = &centroidSet{} // old server: flat-only
	}

	c.mu.Lock()
	if !c.centroidsLoaded {
		c.centroids, c.centroidsLoaded = cs, true
	} else {
		cs = c.centroids
	}
	c.mu.Unlock()
	return cs, nil
}
