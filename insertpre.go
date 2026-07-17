package runespace

import (
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// PreEncryptedItem is an item that was already FHE-encrypted by an EncKey
// holder elsewhere (e.g. rune-mcp on a developer machine). It lets a caller
// that holds no keys at all — the Console forwarding path — append the item
// verbatim: the SDK never sees the plaintext and performs no encryption,
// normalization, or centroid routing for it.
//
// The caller is responsible for the full Insert contract the server enforces:
// the blobs are ITEM-encoded for this instance's key set and dimension, the
// vector was l2-normalized before encryption, and ClusterID was assigned
// against the centroid set identified by CentroidSetVersion.
type PreEncryptedItem struct {
	// ID is the caller-generated opaque UUID. Required: the server treats a
	// re-insert of an existing id as a no-op, so an ack-loss retry MUST reuse
	// the same id to stay idempotent. Generate it once at the origin (mcp)
	// and carry it through every hop and retry.
	ID string

	RMPBlob []byte // Keys.EncryptFlat output (flat tier ITEM encoding)
	MMBlob  []byte // Keys.EncryptClustered output (compact MM row)

	ClusterID          uint32 // hard single assignment, 0..nlist-1
	CentroidSetVersion string // set version the assignment was routed against

	// Metadata is stored verbatim in the server manifest. Opaque to the SDK —
	// in the Rune stack this is the client-sealed {"a","c"} envelope.
	Metadata string
}

// validate reports the first missing piece of the server's Insert contract so
// a bad forward fails before the RPC with an actionable message.
func (it PreEncryptedItem) validate() error {
	if it.ID == "" {
		return fmt.Errorf("runespace: pre-encrypted insert: id is required (idempotent retry key)")
	}
	if len(it.RMPBlob) == 0 {
		return fmt.Errorf("runespace: pre-encrypted insert %s: rmp blob is empty", it.ID)
	}
	if len(it.MMBlob) == 0 {
		return fmt.Errorf("runespace: pre-encrypted insert %s: mm blob is empty (clustered tier is mandatory)", it.ID)
	}
	if it.CentroidSetVersion == "" {
		return fmt.Errorf("runespace: pre-encrypted insert %s: centroid_set_version is empty", it.ID)
	}
	if it.Metadata != "" && !json.Valid([]byte(it.Metadata)) {
		return ErrInvalidMetadata
	}
	return nil
}

// InsertPreEncrypted appends an item encrypted elsewhere, retrying on
// UNAVAILABLE with the same id (idempotent — see PreEncryptedItem.ID). Unlike
// Insert it needs no bound key set and fetches no centroids: everything the
// server checks was produced by the origin encryptor. Options (e.g.
// WithFilterTags) apply the same way as for Insert; tags are trusted as sent,
// so only a trusted caller (the Console) should set them.
func (c *Client) InsertPreEncrypted(ctx context.Context, it PreEncryptedItem, opts ...InsertOption) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return ErrClientClosed
	}
	if err := it.validate(); err != nil {
		return err
	}

	req := &pb.InsertRequest{
		Id:       it.ID,
		Metadata: it.Metadata,
		RmpItem:  &pb.RMPItem{Item: it.RMPBlob},
		MmItem: &pb.MMItem{
			Item:               it.MMBlob,
			ClusterId:          it.ClusterID,
			CentroidSetVersion: it.CentroidSetVersion,
		},
	}
	for _, opt := range opts {
		opt(req)
	}
	return c.insertWithRetry(ctx, req)
}
