package runespace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// Client is a high-level client for the RuneSpace encrypted vector
// index service. It owns a gRPC connection plus the key set bound by
// RegisterKeys, and handles FHE encrypt/decrypt internally: callers pass
// plaintext vectors to Insert/Search and receive plaintext scores back.
//
// RuneSpace exposes a single logical index per instance. A Client is
// safe for concurrent use; Close must not race with in-flight calls.
type Client struct {
	conn *grpc.ClientConn
	svc  pb.RuneSpaceServiceClient

	mu   sync.Mutex
	keys *Keys // bound by RegisterKeys; used for encrypt/decrypt
	// centroids caches the server's IVF centroid set (fetched once via
	// GetCentroids) so Insert can route in plaintext. centroidsLoaded marks the
	// cache populated — a disabled clustered tier is a valid cached value.
	centroids       *centroidSet
	centroidsLoaded bool
}

// Dial connects to a RuneSpace server over TLS (system certificate pool). The
// connection is lazy (grpc.NewClient); the first RPC establishes it.
//
// For local development against a plaintext server, WithInsecure disables
// transport security — see its doc for the safety caveats.
func Dial(addr string, opts ...ClientOption) (*Client, error) {
	if addr == "" {
		return nil, ErrAddressRequired
	}
	o := defaultClientOptions()
	for _, opt := range opts {
		opt(&o)
	}

	// transportCreds defaults to TLS (system cert pool). WithInsecure swaps in a
	// plaintext transport for local development only — see WithInsecure.
	transportCreds := insecure.NewCredentials()
	if !o.Insecure {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("runespace: load system cert pool: %w", err)
		}
		transportCreds = credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(o.MaxMsgSize),
			grpc.MaxCallSendMsgSize(o.MaxMsgSize),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    o.KeepaliveTime,
			Timeout: o.KeepaliveTimeout,
		}),
	}

	var interceptors []grpc.UnaryClientInterceptor
	if o.AccessToken != "" {
		interceptors = append(interceptors, bearerTokenInterceptor(o.AccessToken))
	}
	interceptors = append(interceptors, o.UnaryInterceptors...)
	if len(interceptors) > 0 {
		dialOpts = append(dialOpts, grpc.WithChainUnaryInterceptor(interceptors...))
	}

	// Streaming RPCs (RegisterKeysStream, GetCentroids) are distinct HTTP/2
	// requests, so the bearer token must ride on them too — otherwise an edge
	// gateway verifying a JWT per request rejects the stream.
	var streamInterceptors []grpc.StreamClientInterceptor
	if o.AccessToken != "" {
		streamInterceptors = append(streamInterceptors, bearerTokenStreamInterceptor(o.AccessToken))
	}
	streamInterceptors = append(streamInterceptors, o.StreamInterceptors...)
	if len(streamInterceptors) > 0 {
		dialOpts = append(dialOpts, grpc.WithChainStreamInterceptor(streamInterceptors...))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("runespace: dial %s: %w", addr, err)
	}
	return &Client{
		conn: conn,
		svc:  pb.NewRuneSpaceServiceClient(conn),
	}, nil
}

// Close tears down the gRPC connection. It does not close the bound key set —
// the caller owns that. Idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// connOK reports whether the client is still open. c.conn is read under c.mu
// because Close nils it concurrently; c.svc is set once at Dial and never
// mutated, so callers use it without the lock (an RPC on a just-closed conn
// fails cleanly rather than racing).
func (c *Client) connOK() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Info returns engine build metadata, a live cgo self-check, and whether eval
// keys are registered (GetInfo RPC).
func (c *Client) Info(ctx context.Context) (*Info, error) {
	if !c.connOK() {
		return nil, ErrClientClosed
	}
	resp, err := c.svc.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return nil, err
	}
	info := &Info{
		Version:        resp.GetVersion(),
		Commit:         resp.GetCommit(),
		BuildDate:      resp.GetBuildDate(),
		EngineStatus:   resp.GetEngineStatus(),
		EngineProbeDim: resp.GetEngineProbeDim(),
		Ready:          resp.GetReady(),
	}
	for _, rk := range resp.GetRegisteredKeys() {
		info.RegisteredKeys = append(info.RegisteredKeys, RegisteredKey{
			Kind:        keyKindName(rk.GetKind()),
			KeyID:       rk.GetKid(),
			Preset:      rk.GetPreset(),
			Dim:         int(rk.GetDim()),
			EvalMode:    rk.GetEvalMode(),
			Fingerprint: rk.GetFingerprint(),
		})
	}
	return info, nil
}

// keyKindName maps the proto KeyKind enum to the SDK's short kind name.
func keyKindName(k pb.KeyKind) string {
	switch k {
	case pb.KeyKind_KEY_KIND_RMP_EVAL:
		return rmpKind.name
	case pb.KeyKind_KEY_KIND_MM_EVAL:
		return mmKind.name
	default:
		return "unknown"
	}
}

// registerKeyChunkSize is the per-message payload for RegisterKeysStream. 1 MiB
// stays far under the server's message limit while keeping per-message memory
// tiny — the point of streaming the (hundreds-of-MB) MM eval key.
const registerKeyChunkSize = 1 << 20

// RegisterKeys uploads the PUBLIC RMP and MM eval keys and binds the key set to
// this client for subsequent encrypt/decrypt. The eval keys are streamed from
// disk in chunks (the MM eval key is too large for a single message) and read
// lazily — nothing eval-related is held in memory before or after this call.
// Required before Insert / Search / Delete.
func (c *Client) RegisterKeys(ctx context.Context, keys *Keys) error {
	if !c.connOK() {
		return ErrClientClosed
	}
	if keys == nil || keys.rmp == nil || keys.mm == nil {
		return ErrKeysNotForRegister
	}
	stream, err := c.svc.RegisterKeysStream(ctx)
	if err != nil {
		return err
	}
	if err := streamEvalKey(stream, keyHeaderFor(keys, keys.rmp, pb.KeyKind_KEY_KIND_RMP_EVAL), keys.rmp.dir); err != nil {
		return err
	}
	if err := streamEvalKey(stream, keyHeaderFor(keys, keys.mm, pb.KeyKind_KEY_KIND_MM_EVAL), keys.mm.dir); err != nil {
		return err
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		return err
	}
	c.UseKeys(keys)
	return nil
}

// UseKeys binds a key set to this client for local FHE encrypt/decrypt on
// Insert/Search/Delete, WITHOUT registering anything with the server. Use it on
// clients that share a key set the server already knows: the eval key is
// registered once (by one client, via RegisterKeys), and every other client that
// shares the same on-disk keys binds them with UseKeys to operate on the index.
func (c *Client) UseKeys(keys *Keys) {
	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
}

// VerifyKeys confirms the instance is serving THIS key set: it fetches the
// server's registered-key metadata (GetInfo) and checks every registered key
// against the local bundle — kid, preset, dim, eval mode, and the sha256
// fingerprint of the eval key bytes. It returns nil on a full match, or an error
// describing the first discrepancy (no registered keys, kind mismatch, identity
// mismatch, or a fingerprint mismatch meaning the server holds a different key).
// Computing the fingerprint reads each eval key from disk (the MM key is large).
func (c *Client) VerifyKeys(ctx context.Context, keys *Keys) error {
	if !c.connOK() {
		return ErrClientClosed
	}
	if keys == nil || keys.rmp == nil || keys.mm == nil {
		return ErrKeysNotForRegister
	}
	info, err := c.Info(ctx)
	if err != nil {
		return err
	}
	if len(info.RegisteredKeys) == 0 {
		return fmt.Errorf("runespace: server reports no registered keys")
	}
	local := make(map[string]RegisteredKey, 2)
	for _, b := range []*keyBundle{keys.rmp, keys.mm} {
		fp, err := evalKeyFingerprint(b.dir)
		if err != nil {
			return fmt.Errorf("runespace: fingerprint %s key: %w", b.kind.name, err)
		}
		local[b.kind.name] = RegisteredKey{
			Kind: b.kind.name, KeyID: keys.id, Preset: b.kind.preset,
			Dim: keys.dim, EvalMode: b.kind.evalMode, Fingerprint: fp,
		}
	}
	for _, rk := range info.RegisteredKeys {
		lm, ok := local[rk.Kind]
		if !ok {
			return fmt.Errorf("runespace: server registered a %q key not in the local set", rk.Kind)
		}
		if rk.KeyID != lm.KeyID || rk.Preset != lm.Preset || rk.Dim != lm.Dim || rk.EvalMode != lm.EvalMode {
			return fmt.Errorf("runespace: %q key identity mismatch: server{kid=%s preset=%s dim=%d mode=%s} local{kid=%s preset=%s dim=%d mode=%s}",
				rk.Kind, rk.KeyID, rk.Preset, rk.Dim, rk.EvalMode, lm.KeyID, lm.Preset, lm.Dim, lm.EvalMode)
		}
		if len(rk.Fingerprint) > 0 && !bytes.Equal(rk.Fingerprint, lm.Fingerprint) {
			return fmt.Errorf("runespace: %q key fingerprint mismatch — the instance is serving a different key", rk.Kind)
		}
	}
	return nil
}

// evalKeyFingerprint streams the raw eval key bytes from dir and returns their
// sha256 — the same digest the server records as the key's fingerprint.
func evalKeyFingerprint(dir string) ([]byte, error) {
	r, _, cleanup, err := openEvalKeyReader(dir)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// keyHeaderFor builds the stream header for one key: its kind plus the identity
// (kid/preset/dim/eval_mode) the server records as KeyMeta. TotalLen is filled
// in by streamEvalKey once the on-disk size is known.
func keyHeaderFor(keys *Keys, b *keyBundle, kind pb.KeyKind) *pb.KeyHeader {
	return &pb.KeyHeader{
		Kind:     kind,
		Kid:      keys.id,
		Preset:   b.kind.preset,
		Dim:      uint32(keys.dim),
		EvalMode: b.kind.evalMode,
	}
}

// streamEvalKey sends one eval key as a header, 1 MiB data chunks read straight
// from disk (hashing as it goes), then a footer carrying the sha256 the server
// verifies. The on-disk reader is released as soon as the key is sent.
func streamEvalKey(stream pb.RuneSpaceService_RegisterKeysStreamClient, hdr *pb.KeyHeader, dir string) error {
	r, size, cleanup, err := openEvalKeyReader(dir)
	if err != nil {
		return err
	}
	defer cleanup()

	hdr.TotalLen = uint64(size)
	if err := stream.Send(&pb.RegisterKeysStreamRequest{
		Payload: &pb.RegisterKeysStreamRequest_Header{Header: hdr},
	}); err != nil {
		return err
	}
	h := sha256.New()
	buf := make([]byte, registerKeyChunkSize)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			if err := stream.Send(&pb.RegisterKeysStreamRequest{
				Payload: &pb.RegisterKeysStreamRequest_Data{Data: buf[:n]},
			}); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("runespace: read eval key: %w", rerr)
		}
	}
	return stream.Send(&pb.RegisterKeysStreamRequest{
		Payload: &pb.RegisterKeysStreamRequest_Footer{Footer: &pb.KeyFooter{Sha256: h.Sum(nil)}},
	})
}

// InsertOption configures an optional Insert parameter.
type InsertOption func(*pb.InsertRequest)

// WithFilterTags attaches an opaque filter-tag set (visibility labels) to an insert.
// Empty (the default) = public: the item survives every search scope. A scoped search
// sees the item only if its scope shares ≥1 tag with it (or the item is public). The
// engine never interprets the tags. See Client.Search / WithScope.
func WithFilterTags(tags ...string) InsertOption {
	return func(r *pb.InsertRequest) { r.FilterTags = tags }
}

// SearchOption configures an optional Search parameter.
type SearchOption func(*pb.SearchRequest)

// WithScope restricts a search to the given filter-tag scope: an item is returned only
// if it is public (no tags) or shares ≥1 tag with scope. Omitted/empty = no filter
// (every live hit). Scope is trusted as sent — its provenance is the caller's job.
func WithScope(scope ...string) SearchOption {
	return func(r *pb.SearchRequest) { r.FilterScope = scope }
}

// Insert encrypts the embedding locally and appends it under a fresh SDK-issued
// opaque UUID, which it returns. It sends both the flat (RMP) representation and
// the compact clustered (MM) representation plus the plaintext cluster id it routes
// to, fetched-and-cached from the server's centroid set. A clustered tier is
// mandatory: every insert carries an MM single, so an instance with no centroid set
// is rejected with ErrClusterRequired before any RPC. The id is generated
// client-side so a transient-failure retry reuses the same id and stays idempotent
// (the server treats a re-insert of an existing id as a no-op); Insert retries the
// RPC on UNAVAILABLE with that same id for this reason. metadata is an optional
// plaintext JSON document stored verbatim in the manifest — pass "" for none;
// keep secrets in the encrypted vector, not here. Requires RegisterKeys first;
// len(vec) must equal the key set dimension.
func (c *Client) Insert(ctx context.Context, vec []float32, metadata string, opts ...InsertOption) (string, error) {
	c.mu.Lock()
	conn, keys := c.conn, c.keys
	c.mu.Unlock()
	if conn == nil {
		return "", ErrClientClosed
	}
	if keys == nil {
		return "", ErrKeysNotRegistered
	}
	if len(vec) != keys.Dim() {
		return "", fmt.Errorf("%w: got %d, want %d", ErrDimMismatch, len(vec), keys.Dim())
	}
	if metadata != "" && !json.Valid([]byte(metadata)) {
		return "", ErrInvalidMetadata
	}
	// RuneSpace scores by inner product, so normalize to unit length before
	// encrypting: the stored item and its cluster assignment then live in the same
	// normalized space as the (normalized) query, making scores cosine similarities.
	vec = l2normalize(vec)
	rmpItem, err := keys.EncryptFlat(vec)
	if err != nil {
		return "", fmt.Errorf("runespace: encrypt flat item: %w", err)
	}
	id := uuid.NewString()
	req := &pb.InsertRequest{Id: id, Metadata: metadata, RmpItem: &pb.RMPItem{Item: rmpItem}}

	// Dual-rep: every insert carries the compact MM representation plus the plaintext
	// cluster routing the server stores for IVF, so a configured clustered tier is
	// mandatory. A flat-only instance (or one predating GetCentroids) cannot accept
	// inserts — fail client-side before the doomed RPC.
	cs, err := c.centroidSetCached(ctx)
	if err != nil {
		return "", err
	}
	if !cs.enabled() {
		return "", ErrClusterRequired
	}
	if cs.dim != len(vec) {
		return "", fmt.Errorf("%w: centroid set dim %d, vector %d", ErrDimMismatch, cs.dim, len(vec))
	}
	mmItem, err := keys.EncryptClustered(vec)
	if err != nil {
		return "", fmt.Errorf("runespace: encrypt clustered item: %w", err)
	}
	req.MmItem = &pb.MMItem{Item: mmItem, ClusterId: cs.assign(vec), CentroidSetVersion: cs.version}
	for _, opt := range opts {
		opt(req)
	}

	if err := c.insertWithRetry(ctx, req); err != nil {
		return "", err
	}
	return id, nil
}

// insertWithRetry sends req, retrying on UNAVAILABLE with the SAME request (and
// thus the same id) so a re-send is an idempotent no-op rather than a duplicate.
func (c *Client) insertWithRetry(ctx context.Context, req *pb.InsertRequest) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 50 * time.Millisecond):
			}
		}
		if _, err := c.svc.Insert(ctx, req); err == nil {
			return nil
		} else {
			lastErr = err
			if isCentroidVersionMismatch(err) {
				// The server replaced its centroid set; retrying the same
				// request can never succeed. Surface the typed sentinel so the
				// caller can invalidate, re-route, and retry once.
				return fmt.Errorf("runespace: insert %s: %s: %w", req.GetId(), status.Convert(err).Message(), ErrCentroidVersionMismatch)
			}
			if status.Code(err) != codes.Unavailable {
				return err
			}
		}
	}
	return lastErr
}

// Search runs the blind search and merges the hits across tiers. The query is
// L2-normalized and sent plaintext (PCMM); the server QUERY-encodes it per tier,
// always scans the flat (RMP) tier, and — when it has a centroid set — also probes
// the nearest clusters it selects itself (the probe count is server config, not a
// client choice). Each tier's scores are decrypted, its epoch-pinned dead rows
// dropped, then all sources are merged, ranked, deduped by id (an item served by
// both flat and a cluster appears once, at its best score), and resolved to
// (id, metadata) via GetMetadata. topK <= 0 returns every live hit. Requires
// RegisterKeys first; len(vec) must equal the key set dimension.
func (c *Client) Search(ctx context.Context, vec []float32, topK int, opts ...SearchOption) ([]Match, error) {
	c.mu.Lock()
	conn, keys := c.conn, c.keys
	c.mu.Unlock()
	if conn == nil {
		return nil, ErrClientClosed
	}
	if keys == nil {
		return nil, ErrKeysNotRegistered
	}
	if len(vec) != keys.Dim() {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrDimMismatch, len(vec), keys.Dim())
	}
	// Under PCMM the query is plaintext to the server, so send the raw (unit-
	// normalized) vector and let the server QUERY-encode it per tier (flat IP0 +
	// clustered IP1) and select the probed clusters itself. Normalizing makes the
	// returned inner-product scores cosine similarities.
	req := &pb.SearchRequest{Query: l2normalize(vec)}
	for _, opt := range opts {
		opt(req)
	}
	return c.searchAndResolve(ctx, req, keys, topK)
}

// searchAndResolve runs one blind Search, decrypts and ranks the per-cell score
// blobs, then resolves the ranked candidates to (id, metadata) via GetMetadata,
// deduping cross-tier copies and truncating to topK. It resolves in windows of
// topK*2 (the cross-tier dedup margin). A rebalance swap can retire a cell between
// the Search and GetMetadata RPCs, leaving some positions unresolvable (empty id);
// rather than re-run Search (recomputing scores), it backfills from the already-
// scored lower-ranked candidates with another GetMetadata round-trip, until topK
// is met or the candidates are exhausted.
func (c *Client) searchAndResolve(ctx context.Context, req *pb.SearchRequest, keys *Keys, topK int) ([]Match, error) {
	resp, err := c.svc.Search(ctx, req)
	if err != nil {
		return nil, err
	}

	// Each tier returns one CellResult per live cell (cell_id + encrypted blob +
	// dead rows). RMP and MM use different CKKS contexts, so each decodes with its
	// own key; dead rows are in that cell's own local row coordinates. A hit is
	// addressed by (cell_id, row) within its tier.
	var cands []cand
	for _, cell := range resp.GetRmp() {
		scores, err := keys.DecryptResult(cell.GetBlob())
		if err != nil {
			return nil, fmt.Errorf("runespace: decrypt flat cell %d: %w", cell.GetCellId(), err)
		}
		cands = appendCands(cands, true, cell.GetCellId(), scores, cell.GetDead())
	}
	for _, cell := range resp.GetMm() {
		scores, err := keys.DecryptClustered(cell.GetBlob())
		if err != nil {
			return nil, fmt.Errorf("runespace: decrypt cluster cell %d: %w", cell.GetCellId(), err)
		}
		cands = appendCands(cands, false, cell.GetCellId(), scores, cell.GetDead())
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })

	// batch is the per-round-trip resolve size: topK*2 leaves room for cross-tier
	// dedup, so the common (no-drop) case resolves everything in one GetMetadata.
	// topK<=0 ("every live hit") and an overflowing topK*2 fall back to resolving
	// all candidates at once.
	batch := len(cands)
	if topK > 0 {
		if w := topK * 2; w > 0 && w < len(cands) {
			batch = w
		}
	}

	out := make([]Match, 0, batch)
	seen := make(map[string]struct{}, batch)
	for cursor := 0; cursor < len(cands); cursor += batch {
		hi := cursor + batch
		if hi > len(cands) {
			hi = len(cands)
		}
		ids, metas, err := c.resolvePositions(ctx, cands[cursor:hi], req.GetFilterScope())
		if err != nil {
			return nil, err
		}
		for j, id := range ids {
			if id == "" {
				continue // cell retired between Search and GetMetadata; backfill fills the gap
			}
			if _, dup := seen[id]; dup {
				continue // double-served by flat + a cluster → keep the first (highest score)
			}
			seen[id] = struct{}{}
			pos := cands[cursor+j]
			m := Match{ID: id, Metadata: metas[j], Row: pos.row, Score: pos.score, ClusterID: FlatClusterID}
			if !pos.flat {
				m.ClusterID = int32(pos.cellID) // cluster-tier source cell id (non-flat sentinel)
			}
			out = append(out, m)
			if topK > 0 && len(out) >= topK {
				return out, nil
			}
		}
	}
	return out, nil
}

// resolvePositions resolves one batch of candidate positions to their ids and
// metadata in a single GetMetadata round-trip. The returned slices are aligned to
// positions (an empty id marks a position the server could not resolve).
func (c *Client) resolvePositions(ctx context.Context, positions []cand, scope []string) (ids, metas []string, err error) {
	var rmpRows, mmRows []*pb.CellRow
	for i := range positions {
		cr := &pb.CellRow{CellId: positions[i].cellID, Row: positions[i].row}
		if positions[i].flat {
			rmpRows = append(rmpRows, cr)
		} else {
			mmRows = append(mmRows, cr)
		}
	}
	// Carry the same scope as the Search so the server's second gate blanks any
	// out-of-scope position (so a dead position can't be re-resolved to its id).
	meta, err := c.svc.GetMetadata(ctx, &pb.GetMetadataRequest{RmpRows: rmpRows, MmRows: mmRows, FilterScope: scope})
	if err != nil {
		return nil, nil, err
	}
	rmpEntries, mmEntries := meta.GetRmpEntries(), meta.GetMmEntries()

	ids = make([]string, len(positions))
	metas = make([]string, len(positions))
	var ri, mi int // cursors into rmpEntries / mmEntries, advancing in position order
	for i := range positions {
		var ent *pb.MetadataEntry
		if positions[i].flat {
			if ri < len(rmpEntries) {
				ent = rmpEntries[ri]
			}
			ri++
		} else {
			if mi < len(mmEntries) {
				ent = mmEntries[mi]
			}
			mi++
		}
		if ent != nil {
			ids[i] = ent.GetId()
			metas[i] = ent.GetMetadata()
		}
	}
	return ids, metas, nil
}

// isDead reports whether local row is dead per the packed wire bitmap: bit row lives in
// byte row/8 at LSB-first offset row%8. A row beyond the bitmap length is live (the
// server sizes the buffer to the highest dead position).
func isDead(dead []byte, row int64) bool {
	if row < 0 {
		return false
	}
	b := row / 8
	if b >= int64(len(dead)) {
		return false
	}
	return dead[b]&(1<<(uint(row)%8)) != 0
}

// cand is an internal pre-resolution hit: a decrypted score at a (cell_id, row)
// position in one tier (flat=true ⇒ RMP/IP0, else MM/IP1).
type cand struct {
	flat   bool
	cellID uint32
	row    int64
	score  float64
}

// appendCands adds one cell's live (non-dead) scored rows to dst, dropping positions
// set in the cell's packed dead bitmap.
func appendCands(dst []cand, flat bool, cellID uint32, scores []float64, dead []byte) []cand {
	for i, s := range scores {
		row := int64(i)
		if isDead(dead, row) {
			continue
		}
		dst = append(dst, cand{flat: flat, cellID: cellID, row: row, score: s})
	}
	return dst
}

// Delete soft-deletes id (a plaintext tombstone the server folds into the
// dead-slot filter at query time). Idempotent server-side: deleting an unknown
// or already-deleted id is a no-op success.
func (c *Client) Delete(ctx context.Context, id string) error {
	if !c.connOK() {
		return ErrClientClosed
	}
	_, err := c.svc.Delete(ctx, &pb.DeleteRequest{Id: id})
	return err
}

// UpdateTags changes an item's opaque filter-tag set: add and remove are applied to the
// current set (add wins on overlap); both are idempotent. An unknown id is a no-op
// success. Tags are a query-time visibility filter, so this moves no data and triggers
// no rebalance; a removed tag stops matching immediately (memory-first server-side).
func (c *Client) UpdateTags(ctx context.Context, id string, add, remove []string) error {
	if !c.connOK() {
		return ErrClientClosed
	}
	_, err := c.svc.UpdateTags(ctx, &pb.UpdateTagsRequest{Id: id, Add: add, Remove: remove})
	return err
}

// RetagAll replaces filter tag from with to on every item that currently carries
// from, returning how many items changed. Bulk, applied per item server-side
// (memory-first then durable; idempotent and re-runnable) — an item already holding
// to keeps a single copy. from and to are required and must differ; use RemoveTag to
// strip a tag entirely. Tags are a query-time visibility filter, so this moves no
// data and triggers no rebalance.
func (c *Client) RetagAll(ctx context.Context, from, to string) (uint64, error) {
	if !c.connOK() {
		return 0, ErrClientClosed
	}
	resp, err := c.svc.RetagAll(ctx, &pb.RetagAllRequest{From: from, To: to})
	if err != nil {
		return 0, err
	}
	return resp.GetChanged(), nil
}

// RemoveTag strips filter tag tag from every item that currently carries it,
// returning how many items changed. Bulk, applied per item server-side (memory-first
// then durable; idempotent and re-runnable). tag is required.
func (c *Client) RemoveTag(ctx context.Context, tag string) (uint64, error) {
	if !c.connOK() {
		return 0, ErrClientClosed
	}
	resp, err := c.svc.RemoveTag(ctx, &pb.RemoveTagRequest{Tag: tag})
	if err != nil {
		return 0, err
	}
	return resp.GetChanged(), nil
}

// bearerTokenInterceptor injects an "authorization: Bearer <token>" header on
// every unary RPC.
func bearerTokenInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// bearerTokenStreamInterceptor injects an "authorization: Bearer <token>" header
// on every streaming RPC — the streaming counterpart of bearerTokenInterceptor,
// so client- and server-streaming calls authenticate exactly like unary ones.
func bearerTokenStreamInterceptor(token string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
