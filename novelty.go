package runespace

import (
	"context"
	"crypto/sha256"
	"fmt"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// The novelty tier is the dim-major, sign-only side of the engine: the key-holder
// encrypts whole shards and uploads them, the KEYLESS server scores a plaintext
// query across them and returns one blinded blob per shard, and the key-holder
// reveals a count from those blobs. The server learns neither the vectors nor the
// count.
//
// This file is the TRANSPORT half only. Producing a shard blob (transpose in
// clear → encrypt one SLOT column per dimension → serialize) and revealing a count
// from the returned blobs both need the novelty crypto, which is not yet vendored
// for this SDK's platforms; those calls land with it.

// shardChunkSize is the per-message payload for PutShardStream. 1 MiB matches the
// eval-key stream: far under the server's message limit, while a dim-major shard
// is many MB (one full-chain SLOT column per dimension).
const shardChunkSize = 1 << 20

// LeanKeyMeta identifies a novelty-tier eval key. The fingerprint is derived from
// the key bytes at registration, so it is not carried here.
type LeanKeyMeta struct {
	KeyID    string
	Preset   string
	Dim      int
	EvalMode string
}

// RegisterLeanKey uploads the PUBLIC novelty-tier eval key and opens that tier's
// data plane. Independent of RegisterKeys (the RMP+MM registration): an instance
// can serve novelty with neither of those present, and vice versa. The key is
// small — the tier is key-switch-free, so no rotation keys ship — so it goes in
// one message; the server checks it against the sha256 sent with meta.
func (c *Client) RegisterLeanKey(ctx context.Context, evalKey []byte, meta LeanKeyMeta) error {
	if !c.connOK() {
		return ErrClientClosed
	}
	if len(evalKey) == 0 {
		return fmt.Errorf("runespace: lean eval key is empty")
	}
	sum := sha256.Sum256(evalKey)
	_, err := c.svc.RegisterLeanKey(ctx, &pb.RegisterLeanKeyRequest{
		EvalKey: evalKey,
		Meta: &pb.KeyMeta{
			Kind:        pb.KeyKind_KEY_KIND_LEAN_EVAL,
			Kid:         meta.KeyID,
			Preset:      meta.Preset,
			Dim:         uint32(meta.Dim),
			EvalMode:    meta.EvalMode,
			Fingerprint: sum[:],
		},
	})
	return err
}

// UploadShard stores one client-encrypted dim-major shard at a client-assigned
// index: sealed shards 0..k-1 are immutable, and the open shard k is re-uploaded
// at its index on every insert until it seals. index must be within [0, n] against
// the server's current shard count — appending past that is rejected as a gap.
// blob is the serialized shard; it is streamed, and the server verifies the
// declared length and sha256 before storing anything.
func (c *Client) UploadShard(ctx context.Context, index int, blob []byte) error {
	if !c.connOK() {
		return ErrClientClosed
	}
	if index < 0 {
		return fmt.Errorf("runespace: shard index must be >= 0, got %d", index)
	}
	if len(blob) == 0 {
		return fmt.Errorf("runespace: shard is empty")
	}
	stream, err := c.svc.PutShardStream(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.PutShardStreamRequest{
		Payload: &pb.PutShardStreamRequest_Header{Header: &pb.ShardHeader{
			Index:    uint32(index),
			TotalLen: uint64(len(blob)),
		}},
	}); err != nil {
		return err
	}
	sum := sha256.New()
	for off := 0; off < len(blob); off += shardChunkSize {
		end := min(off+shardChunkSize, len(blob))
		chunk := blob[off:end]
		if err := stream.Send(&pb.PutShardStreamRequest{
			Payload: &pb.PutShardStreamRequest_Data{Data: chunk},
		}); err != nil {
			return err
		}
		_, _ = sum.Write(chunk)
	}
	if err := stream.Send(&pb.PutShardStreamRequest{
		Payload: &pb.PutShardStreamRequest_Footer{Footer: &pb.ShardFooter{Sha256: sum.Sum(nil)}},
	}); err != nil {
		return err
	}
	_, err = stream.CloseAndRecv()
	return err
}

// NoveltyBlobs scores a plaintext query against every stored shard and returns one
// sign-only blinded blob per shard. tau is the novelty threshold on the inner
// product; rBits is the per-element blind width (its ceiling is density-dependent,
// around 8-12). The query is plaintext to the keyless server by design.
//
// It returns the blobs rather than a count because only a key-holder can reveal
// them — sum the per-blob reveals to get the number of stored items whose
// similarity to the query exceeds tau.
func (c *Client) NoveltyBlobs(ctx context.Context, query []float64, tau float64, rBits int) ([][]byte, error) {
	if !c.connOK() {
		return nil, ErrClientClosed
	}
	if len(query) == 0 {
		return nil, fmt.Errorf("runespace: query is empty")
	}
	resp, err := c.svc.Novelty(ctx, &pb.NoveltyRequest{
		Query: query,
		Tau:   tau,
		RBits: uint32(rBits),
	})
	if err != nil {
		return nil, err
	}
	return resp.GetBlobs(), nil
}
