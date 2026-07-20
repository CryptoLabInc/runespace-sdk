package runespace

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/CryptoLabInc/runespace-sdk/internal/crypto"
)

// keyKind is one CKKS parameter family. The kind fixes its preset, eval mode and
// on-disk location: rmp = IP0/RMP under rmp/, mm = IP1/MM under mm/. Both
// bundles build the requested Encryptor and Decryptor on open: the RMP one
// handles flat-tier rmp_item payloads and score blobs, while the MM one handles
// compact clustered-tier mm_item payloads and per-cluster search results.
type keyKind struct {
	name     string
	preset   string
	evalMode string
	subdir   string // "" → key root; else a subdirectory of WithKeyPath
}

var (
	rmpKind = keyKind{name: "rmp", preset: "ip0", evalMode: "rmp", subdir: "rmp"}
	mmKind  = keyKind{name: "mm", preset: "ip1", evalMode: "mm", subdir: "mm"}
)

func flatBundleKind(flatMode string) keyKind {
	k := rmpKind // default: "rmp"
	if strings.EqualFold(strings.TrimSpace(flatMode), "single") {
		k.evalMode = "flat"
	}
	return k
}

// Key bundle filenames. GenerateKeys writes the JSON envelopes; the raw .bin
// forms are still recognised on open so bundles produced elsewhere continue to
// load.
const (
	encKeyBinFile   = "EncKey.bin"
	evalKeyBinFile  = "EvalKey.bin"
	secKeyBinFile   = "SecKey.bin"
	encKeyJSONFile  = "EncKey.json"
	evalKeyJSONFile = "EvalKey.json"
	secKeyJSONFile  = "SecKey.json"
)

// keyBundle is the on-disk + cgo state for one keyKind. It records the kind and
// the directory its key files live in, plus (for the RMP data path) the cgo
// context and Encryptor/Decryptor built from the Enc/Sec keys. The eval key is
// NOT held here: RegisterKeys lazy-loads it from dir and releases it right after,
// so the large MM eval key never sits in memory. Unexported — callers go through
// Keys.
type keyBundle struct {
	kind keyKind
	dir  string
	ckks crypto.CKKSContext
	enc  crypto.Encryptor
	dec  crypto.Decryptor

	// cryptoMu serializes every cgo crypto call that touches this bundle's
	// evi context (ckks). enc and dec are built from the SAME context, and the
	// underlying evi encryptor/decryptor are not reentrant: two concurrent
	// encrypt/decrypt calls on one context fault natively (SIGBUS). The
	// per-object RWMutex inside cgoEncryptor/cgoDecryptor only guards against
	// Close freeing objects mid-call (it takes RLock, so it permits concurrent
	// calls) — it does NOT serialize the cgo work. This mutex does, at
	// context granularity, so the RMP and MM bundles still run in parallel.
	cryptoMu sync.Mutex
}

func (b *keyBundle) close() {
	if b == nil {
		return
	}
	b.cryptoMu.Lock()
	defer b.cryptoMu.Unlock()
	if b.enc != nil {
		_ = b.enc.Close()
		b.enc = nil
	}
	if b.dec != nil {
		_ = b.dec.Close()
		b.dec = nil
	}
	if b.ckks != nil {
		_ = b.ckks.Close()
		b.ckks = nil
	}
}

// Keys is the fixed key set for one RuneSpace index dimension. It holds the RMP
// (IP0) and MM (IP1) bundles — each a cgo context plus Encryptor/Decryptor — and
// remembers where each bundle's key files live so Client.RegisterKeys can stream
// the (large) eval keys from disk without ever loading them fully into memory.
// There is no load/unload lifecycle: OpenKeys it, register it on a client,
// operate, Close it.
type Keys struct {
	id  string
	dim int
	rmp *keyBundle // IP0 / RMP
	mm  *keyBundle // IP1 / MM
}

// ID returns the key identifier the set was generated with.
func (k *Keys) ID() string { return k.id }

// Dim returns the FHE slot dimension. Client validates Insert/Search
// vector lengths against it.
func (k *Keys) Dim() int { return k.dim }

// EncryptFlat FHE-encrypts one embedding into the ITEM-encoded evi bytes that
// Client.Insert sends as rmp_item — the flat (RMP) tier's per-item wire form.
func (k *Keys) EncryptFlat(vec []float32) ([]byte, error) {
	if k == nil || k.rmp == nil {
		return nil, ErrKeysNotForEncrypt
	}
	k.rmp.cryptoMu.Lock()
	defer k.rmp.cryptoMu.Unlock()
	if k.rmp.enc == nil { // re-check under the lock: close() nils it under cryptoMu
		return nil, ErrKeysNotForEncrypt
	}
	return k.rmp.enc.EncryptSingle(vec, "item")
}

// EncryptClustered compact-encrypts one embedding into the ITEM-encoded evi bytes
// that Client.Insert sends as mm_item — the clustered (MM) tier's per-item wire
// form. Distinct from EncryptFlat: the clustered tier uses encryptRow (one compact
// row), not the RMP batch path. level 1 selects the DB scale the server's
// make_searchable rescales to level 0 at compaction.
func (k *Keys) EncryptClustered(vec []float32) ([]byte, error) {
	if k == nil || k.mm == nil {
		return nil, ErrKeysNotForEncrypt
	}
	k.mm.cryptoMu.Lock()
	defer k.mm.cryptoMu.Unlock()
	if k.mm.enc == nil { // re-check under the lock: close() nils it under cryptoMu
		return nil, ErrKeysNotForEncrypt
	}
	return k.mm.enc.EncryptRow(vec, "item", 1)
}

// Query encoding is intentionally NOT a client method: under PCMM the query is
// plaintext to the server, so Client.Search sends the raw query vector and the
// server QUERY-encodes it per tier (flat IP0 + clustered IP1). The key set only
// encrypts stored items (EncryptFlat / EncryptClustered) and decrypts results.

// DecryptResult decrypts a flat (RMP) Search response blob into per-slot
// inner-product scores. scores[i] is the score for index slot i.
func (k *Keys) DecryptResult(result []byte) ([]float64, error) {
	if k == nil || k.rmp == nil {
		return nil, ErrKeysNotForDecrypt
	}
	k.rmp.cryptoMu.Lock()
	defer k.rmp.cryptoMu.Unlock()
	if k.rmp.dec == nil { // re-check under the lock: close() nils it under cryptoMu
		return nil, ErrKeysNotForDecrypt
	}
	return k.rmp.dec.DecryptSearchResult(result)
}

// DecryptClustered decrypts one clustered (MM) cluster_result blob into per-row
// inner-product scores. scores[r] is the score for (cluster, row r).
func (k *Keys) DecryptClustered(result []byte) ([]float64, error) {
	if k == nil || k.mm == nil {
		return nil, ErrKeysNotForDecrypt
	}
	k.mm.cryptoMu.Lock()
	defer k.mm.cryptoMu.Unlock()
	if k.mm.dec == nil { // re-check under the lock: close() nils it under cryptoMu
		return nil, ErrKeysNotForDecrypt
	}
	return k.mm.dec.DecryptSearchResult(result)
}

// Close releases the cgo handles held by the key set. Idempotent.
func (k *Keys) Close() error {
	if k == nil {
		return nil
	}
	k.rmp.close()
	k.mm.close()
	return nil
}

// resolveKeySlot returns the preferred source path for one key slot, preferring
// the JSON envelope when both formats coexist.
func resolveKeySlot(dir, binName, jsonName string) (path string, isJSON bool, exists bool) {
	jsonPath := filepath.Join(dir, jsonName)
	if _, err := os.Stat(jsonPath); err == nil {
		return jsonPath, true, true
	}
	binPath := filepath.Join(dir, binName)
	if _, err := os.Stat(binPath); err == nil {
		return binPath, false, true
	}
	return "", false, false
}

// KeysExist reports whether the requested RMP-tier key parts (default: all
// three) are present under WithKeyPath's rmp/ subdirectory, in either the .json
// or .bin form.
func KeysExist(opts ...KeysOption) bool {
	o := buildKeysOptions(opts)
	if o.Path == "" {
		return false
	}
	rmpDir := filepath.Join(o.Path, rmpKind.subdir)
	wantEnc, wantEval, wantSec := resolveKeyParts(o.Parts)
	if wantEnc {
		if _, _, ok := resolveKeySlot(rmpDir, encKeyBinFile, encKeyJSONFile); !ok {
			return false
		}
	}
	if wantEval {
		if _, _, ok := resolveKeySlot(rmpDir, evalKeyBinFile, evalKeyJSONFile); !ok {
			return false
		}
	}
	if wantSec {
		if _, _, ok := resolveKeySlot(rmpDir, secKeyBinFile, secKeyJSONFile); !ok {
			return false
		}
	}
	return true
}

// anySlotExists reports whether any of the three key slots is already present
// under dir, in either format. GenerateKeys uses it to avoid overwriting.
func anySlotExists(dir string) bool {
	for _, s := range [][2]string{
		{encKeyBinFile, encKeyJSONFile},
		{evalKeyBinFile, evalKeyJSONFile},
		{secKeyBinFile, secKeyJSONFile},
	} {
		if _, _, ok := resolveKeySlot(dir, s[0], s[1]); ok {
			return true
		}
	}
	return false
}

// GenerateKeys writes a fresh key set at WithKeyPath, one tier per subdirectory:
// the RMP (IP0) trio under rmp/ and the MM (IP1) trio under mm/. Within each,
// EncKey and SecKey are KeyManager JSON envelopes; EvalKey is the raw .bin (its
// KeyPack serialization can't round-trip the envelope, and the MM eval key is
// hundreds of MB). Both tiers are generated by default — RegisterKeys needs both
// eval keys. Returns ErrKeysAlreadyExist if either set is already present; it
// never overwrites.
//
// The generated SecKey files are irreplaceable: losing them makes data encrypted
// under this set permanently unreadable. After generation, back up the complete
// WithKeyPath root (both rmp/ and mm/) to encrypted, access-controlled storage
// and test restores with OpenKeys and Client.VerifyKeys. Generating a new set is
// not a recovery procedure for existing data.
func GenerateKeys(opts ...KeysOption) error {
	o := buildKeysOptions(opts)
	if err := o.validate(); err != nil {
		return err
	}
	rmpDir := filepath.Join(o.Path, flatBundleKind(o.FlatMode).subdir)
	mmDir := filepath.Join(o.Path, mmKind.subdir)
	if anySlotExists(rmpDir) || anySlotExists(mmDir) {
		return ErrKeysAlreadyExist
	}
	// Roll back any partially-written key files on failure so a retry isn't
	// permanently blocked by the anySlotExists guard above (e.g. RMP succeeds
	// but MM fails on a full disk). Registered only after the existence check,
	// so it never touches a caller's pre-existing key set.
	success := false
	defer func() {
		if !success {
			removeKeyArtifacts(rmpDir)
			_ = os.Remove(rmpDir) // best-effort; only removes it if now empty
			removeKeyArtifacts(mmDir)
			_ = os.Remove(mmDir)
		}
	}()

	// RMP tier under rmp/: EncKey/SecKey JSON envelopes, EvalKey.bin raw.
	// The eval mode (RMP | FLAT) follows WithFlatMode.
	if err := generateBundle(o, flatBundleKind(o.FlatMode), true); err != nil {
		return err
	}
	// MM tier under mm/: same layout. EncKey/SecKey are small, so they are
	// enveloped too; only the (huge) EvalKey stays raw .bin.
	if err := generateBundle(o, mmKind, true); err != nil {
		return err
	}
	success = true
	return nil
}

// removeKeyArtifacts best-effort deletes every known key slot file from dir. It
// only names the six key files, so it cannot remove unrelated caller files.
func removeKeyArtifacts(dir string) {
	for _, name := range []string{
		encKeyBinFile, evalKeyBinFile, secKeyBinFile,
		encKeyJSONFile, evalKeyJSONFile, secKeyJSONFile,
	} {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// generateBundle generates one kind's Enc/Eval/Sec trio into <path>/<kind.subdir>.
// With wrapJSON each .bin is wrapped into its .json envelope and the .bin dropped;
// otherwise the raw .bin trio is kept.
func generateBundle(o keysOptions, kind keyKind, wrapJSON bool) error {
	dir := filepath.Join(o.Path, kind.subdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("runespace: mkdir %s key dir: %w", kind.name, err)
	}
	gen, err := crypto.Default().NewKeyGenerator(crypto.KeyGenParams{
		CKKSParams: crypto.CKKSParams{
			Preset:   kind.preset,
			DimList:  []int{o.Dim},
			EvalMode: kind.evalMode,
		},
		KeyPath: dir,
		KeyID:   o.KeyID,
	})
	if err != nil {
		return fmt.Errorf("runespace: new %s key generator: %w", kind.name, err)
	}
	if err := gen.Generate(); err != nil {
		return err
	}
	if !wrapJSON {
		return nil
	}
	// Generate writes EncKey.bin raw and SecKey.json already enveloped. Only
	// EncKey is wrapped into its JSON envelope here (then dropped). EvalKey is
	// left as the raw .bin the KeyPack saver wrote: that serialization is the
	// one the homevaluator loads via buffer, and the KeyManager eval-key
	// envelope cannot round-trip it. RegisterKeys streams the raw .bin directly.
	steps := []struct {
		binFile  string
		jsonFile string
		wrap     func(keyID, binPath, jsonPath string) error
	}{
		{encKeyBinFile, encKeyJSONFile, crypto.WrapEncKey},
	}
	for _, s := range steps {
		binPath := filepath.Join(dir, s.binFile)
		jsonPath := filepath.Join(dir, s.jsonFile)
		if err := s.wrap(o.KeyID, binPath, jsonPath); err != nil {
			return fmt.Errorf("runespace: wrap %s: %w", s.binFile, err)
		}
		if err := os.Remove(binPath); err != nil {
			return fmt.Errorf("runespace: remove %s: %w", s.binFile, err)
		}
	}
	return nil
}

// OpenKeys loads the key set at WithKeyPath and builds a Keys with both the RMP
// (rmp/) and MM (mm/) bundles. Both JSON envelopes and raw .bin files are
// accepted (per-slot format is detected automatically). WithKeyParts narrows
// which encrypt/decrypt materials are loaded per bundle; omitting it loads both
// Enc and Sec. The eval keys are never loaded here — RegisterKeys streams them
// from disk on demand. Returns ErrKeysNotFound when a required slot is absent.
func OpenKeys(opts ...KeysOption) (*Keys, error) {
	o := buildKeysOptions(opts)
	if err := o.validate(); err != nil {
		return nil, err
	}
	rmp, err := openKeyBundle(o, flatBundleKind(o.FlatMode))
	if err != nil {
		return nil, err
	}
	mm, err := openKeyBundle(o, mmKind)
	if err != nil {
		rmp.close()
		return nil, err
	}
	return &Keys{id: o.KeyID, dim: o.Dim, rmp: rmp, mm: mm}, nil
}

// openKeyBundle builds one kind's cgo context plus the requested Encryptor /
// Decryptor from the Enc/Sec keys in <path>/<kind.subdir>. It does NOT load the
// eval key (that is streamed from dir by RegisterKeys).
func openKeyBundle(o keysOptions, kind keyKind) (*keyBundle, error) {
	wantEnc, _, wantSec := resolveKeyParts(o.Parts)
	dir := filepath.Join(o.Path, kind.subdir)

	// Stage the requested slots into a tempdir using canonical .bin names so
	// the path-based cgo loaders can find them regardless of source format.
	stage, err := os.MkdirTemp("", "runespace-keys-*")
	if err != nil {
		return nil, fmt.Errorf("runespace: stage tempdir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(stage) }

	materialise := func(binName, jsonName string, unwrap func(jsonPath, binPath string) error) error {
		srcPath, isJSON, ok := resolveKeySlot(dir, binName, jsonName)
		if !ok {
			return ErrKeysNotFound
		}
		dstPath := filepath.Join(stage, binName)
		if isJSON {
			if err := unwrap(srcPath, dstPath); err != nil {
				return fmt.Errorf("runespace: unwrap %s: %w", jsonName, err)
			}
			return nil
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("runespace: stage %s: %w", binName, err)
		}
		return nil
	}

	if wantEnc {
		if err := materialise(encKeyBinFile, encKeyJSONFile, crypto.UnwrapEncKey); err != nil {
			cleanup()
			return nil, err
		}
	}
	if wantSec {
		if err := materialise(secKeyBinFile, secKeyJSONFile, crypto.UnwrapSecKey); err != nil {
			cleanup()
			return nil, err
		}
	}

	p := crypto.Default()
	ckks, err := p.NewCKKSContext(crypto.CKKSParams{
		Preset:   kind.preset,
		DimList:  []int{o.Dim},
		EvalMode: kind.evalMode,
	})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("runespace: new ckks context: %w", err)
	}

	b := &keyBundle{kind: kind, dir: dir, ckks: ckks}
	if wantEnc {
		enc, err := p.NewEncryptor(ckks, stage)
		if err != nil {
			_ = ckks.Close()
			cleanup()
			return nil, fmt.Errorf("runespace: new encryptor: %w", err)
		}
		b.enc = enc
	}
	if wantSec {
		dec, err := p.NewDecryptor(ckks, stage)
		if err != nil {
			b.close()
			cleanup()
			return nil, fmt.Errorf("runespace: new decryptor: %w", err)
		}
		b.dec = dec
	}

	cleanup()
	return b, nil
}

// openEvalKeyReader opens a reader over the RAW eval-key bytes in dir, its byte
// length, and a cleanup to call when done. A JSON-enveloped slot is unwrapped to
// a temp file (removed by cleanup); a raw .bin slot is streamed in place. Used by
// Client.RegisterKeys so the eval key is read lazily and released right after.
func openEvalKeyReader(dir string) (r io.ReadCloser, size int64, cleanup func(), err error) {
	noop := func() {}
	srcPath, isJSON, ok := resolveKeySlot(dir, evalKeyBinFile, evalKeyJSONFile)
	if !ok {
		return nil, 0, noop, ErrKeysNotFound
	}
	if !isJSON {
		f, err := os.Open(srcPath)
		if err != nil {
			return nil, 0, noop, err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, 0, noop, err
		}
		return f, fi.Size(), func() { _ = f.Close() }, nil
	}
	tmp, err := os.CreateTemp("", "runespace-eval-*.bin")
	if err != nil {
		return nil, 0, noop, fmt.Errorf("runespace: stage eval: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	if err := crypto.UnwrapEvalKey(srcPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, 0, noop, fmt.Errorf("runespace: unwrap eval: %w", err)
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return nil, 0, noop, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, 0, noop, err
	}
	return f, fi.Size(), func() { _ = f.Close(); _ = os.Remove(tmpPath) }, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
