// Package crypto is the internal FHE primitive boundary. Default() returns
// the cgo Provider that binds the bundled libevi static archives.
package crypto

type CKKSParams struct {
	Preset   string
	DimList  []int
	EvalMode string
}

type KeyGenParams struct {
	CKKSParams
	KeyPath string
	KeyID   string
}

type CKKSContext interface {
	Close() error
}

type Encryptor interface {
	// EncryptSingle FHE-encrypts a single vector (evi_encryptor_encrypt_batch_with_pack,
	// one-item batch) and serializes it. The RMP item route — used for the
	// flat-tier rmp_item payload. In MM mode this path returns a full transposed
	// matrix; MM items go through EncryptRow instead.
	EncryptSingle(vec []float32, encodeType string) ([]byte, error)
	// EncryptRow compact-encrypts a single vector (evi::Encryptor::encryptRow via
	// the local encryptor_shim) into one coefficient-domain row ciphertext. The MM
	// item route — used for the clustered-tier mm_item payload. level is the
	// DB-scale flag (1 for stored items).
	EncryptRow(vec []float32, encodeType string, level int) ([]byte, error)
	// Query encoding is NOT a client concern: under PCMM the query is plaintext to
	// the server, so the client sends the raw query vector and the server
	// QUERY-encodes it per tier. The SDK therefore only encrypts stored items.
	Close() error
}

type Decryptor interface {
	// DecryptSearchResult decrypts one serialized evi search_result blob (the
	// RuneSpace Search response) into its per-slot inner-product scores.
	DecryptSearchResult(result []byte) (scores []float64, err error)
	Close() error
}

type KeyGenerator interface {
	Generate() error
}

// Provider builds the four primitive handles that a Keys bundle needs.
// Encryptor and Decryptor take the key directory path rather than the raw
// key bytes because the upstream C API only exposes path-based loaders
// (evi_keypack_create_from_path, evi_secret_key_create_from_path).
// Providers read the individual key files off disk themselves.
type Provider interface {
	NewCKKSContext(CKKSParams) (CKKSContext, error)
	NewEncryptor(ctx CKKSContext, keyDir string) (Encryptor, error)
	NewDecryptor(ctx CKKSContext, keyDir string) (Decryptor, error)
	NewKeyGenerator(KeyGenParams) (KeyGenerator, error)
}

func Default() Provider { return cgoProvider{} }
