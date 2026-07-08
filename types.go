package runespace

// Match is one ranked Search hit. Score is the decrypted inner-product score (a
// cosine similarity for an L2-normalized query). ID and Metadata are resolved
// server-side via GetMetadata for the surviving top-k positions; ID is empty for a
// position with no manifest row, and Metadata is the verbatim plaintext JSON
// document supplied at Insert ("" if none).
type Match struct {
	ID       string
	Metadata string
	// ClusterID discriminates the source tier: FlatClusterID for the flat (RMP)
	// tier, or the source cell id (>= 0) for a clustered (MM) hit. Results are
	// addressed by (cell id, row) per tier; for a cluster hit this carries that cell id.
	ClusterID int32
	// Row is the hit's cell-local row within its source cell.
	Row   int64
	Score float64
}

// Info is the engine status returned by Client.Info (the GetInfo RPC).
type Info struct {
	Version        string
	Commit         string
	BuildDate      string
	EngineStatus   string // "ok" or an error string from the engine self-check
	EngineProbeDim uint32 // dim reported by a throwaway evi context
	Ready          bool   // true once eval keys are registered (data plane open)

	// RegisteredKeys is the identity + fingerprint of each eval key the instance
	// has registered. Empty when unregistered. VerifyKeys compares these against
	// a local key set.
	RegisteredKeys []RegisteredKey
}

// RegisteredKey is the server-reported identity and fingerprint of one
// registered eval key (mirrors the engine's KeyMeta).
type RegisteredKey struct {
	Kind        string // "rmp" or "mm"
	KeyID       string
	Preset      string
	Dim         int
	EvalMode    string
	Fingerprint []byte // sha256 over the raw eval key bytes
}
