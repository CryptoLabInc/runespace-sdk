package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCGO_ContextRoundTrip(t *testing.T) {
	p := Default()
	for i := 0; i < 5; i++ {
		ctx, err := p.NewCKKSContext(CKKSParams{
			Preset:   "ip",
			DimList:  []int{128},
			EvalMode: "rmp",
		})
		if err != nil {
			t.Fatalf("iter %d NewCKKSContext: %v", i, err)
		}
		if err := ctx.Close(); err != nil {
			t.Fatalf("iter %d Close: %v", i, err)
		}
	}
}

func TestCGO_Preset_Invalid(t *testing.T) {
	_, err := Default().NewCKKSContext(CKKSParams{
		Preset:   "qf0", // QF disabled in the active set
		DimList:  []int{128},
		EvalMode: "rmp",
	})
	if err == nil {
		t.Fatal("expected error for qf0 preset")
	}
}

func TestCGO_KeyGen_WritesKeyFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	gen, err := Default().NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{
			Preset:   "ip",
			DimList:  []int{128},
			EvalMode: "rmp",
		},
		KeyPath: dir,
		KeyID:   "smoke",
	})
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Enc/Eval are written raw (the KeyPack savers); the secret key has no raw
	// serializer so it is written as its JSON envelope via the KeyManager shim.
	for _, name := range []string{cgoEncKeyFile, cgoEvalKeyFile, cgoSecKeyJSONFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
	// SecKey.bin must NOT be present — KeyGenerator never dumps a raw secret key.
	if _, err := os.Stat(filepath.Join(dir, cgoSecKeyFile)); err == nil {
		t.Errorf("%s should not exist (secret key is JSON-only)", cgoSecKeyFile)
	}
}

// TestCGO_Encrypt_SingleReturnsNonEmpty generates a key set, opens an Encryptor
// against it, and verifies the RMP ITEM path (EncryptSingle, batch-with-pack)
// returns a non-empty serialized payload. Query encoding is the server's job now,
// so the client encryptor only encrypts stored items.
func TestCGO_Encrypt_SingleReturnsNonEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	p := Default()
	gen, err := p.NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"},
		KeyPath:    dir,
		KeyID:      "enc-smoke",
	})
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ctx, err := p.NewCKKSContext(CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"})
	if err != nil {
		t.Fatalf("NewCKKSContext: %v", err)
	}
	defer ctx.Close()

	enc, err := p.NewEncryptor(ctx, dir)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	defer enc.Close()

	vec := make([]float32, 128)
	for i := range vec {
		vec[i] = float32(i) / 128.0
	}
	item, err := enc.EncryptSingle(vec, "item")
	if err != nil {
		t.Fatalf("EncryptSingle(item): %v", err)
	}
	if len(item) == 0 {
		t.Errorf("EncryptSingle(item) returned empty payload")
	}
}

// TestCGO_Encrypt_MMItemReturnsNonEmpty generates an IP1/MM key set, opens an
// Encryptor against it, and verifies the MM item route (EncryptRow, the
// encryptor_shim path) returns a non-empty compact row ciphertext. EncryptSingle's
// batch route is RMP-only — in MM mode it would return a full transposed matrix —
// so the MM item path must go through EncryptRow.
func TestCGO_Encrypt_MMItemReturnsNonEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	p := Default()
	gen, err := p.NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{Preset: "ip1", DimList: []int{128}, EvalMode: "mm"},
		KeyPath:    dir,
		KeyID:      "mm-row-smoke",
	})
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ctx, err := p.NewCKKSContext(CKKSParams{Preset: "ip1", DimList: []int{128}, EvalMode: "mm"})
	if err != nil {
		t.Fatalf("NewCKKSContext: %v", err)
	}
	defer ctx.Close()

	enc, err := p.NewEncryptor(ctx, dir)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	defer enc.Close()

	vec := make([]float32, 128)
	for i := range vec {
		vec[i] = float32(i) / 128.0
	}
	row, err := enc.EncryptRow(vec, "item", 1)
	if err != nil {
		t.Fatalf("EncryptRow(item): %v", err)
	}
	if len(row) == 0 {
		t.Fatalf("EncryptRow(item) returned empty payload")
	}
	t.Logf("MM encryptRow item blob = %d bytes", len(row))
}

func TestCGO_Decryptor_OpenAgainstGeneratedKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	p := Default()
	gen, _ := p.NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"},
		KeyPath:    dir,
		KeyID:      "dec-smoke",
	})
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Generate writes the secret key as SecKey.json; NewDecryptor loads the raw
	// SecKey.bin, so unwrap the envelope in place first (keys.go does this into a
	// staging dir for the real open path).
	if err := UnwrapSecKey(filepath.Join(dir, cgoSecKeyJSONFile), filepath.Join(dir, cgoSecKeyFile)); err != nil {
		t.Fatalf("UnwrapSecKey: %v", err)
	}

	ctx, err := p.NewCKKSContext(CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"})
	if err != nil {
		t.Fatalf("NewCKKSContext: %v", err)
	}
	defer ctx.Close()

	dec, err := p.NewDecryptor(ctx, dir)
	if err != nil {
		t.Fatalf("NewDecryptor: %v", err)
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
