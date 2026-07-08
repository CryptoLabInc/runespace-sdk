package runespace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func vec128() []float32 {
	v := make([]float32, 128)
	for i := range v {
		v[i] = float32(i) / 128
	}
	return v
}

// TestKeyParts verifies WithKeyParts loads exactly the requested encrypt/decrypt
// materials and that operations needing an unloaded part fail with the right
// guard error. A successful OpenKeys for a given part set is itself proof the cgo
// handle for that part was built (NewEncryptor / NewDecryptor would error
// otherwise). Eval keys are not loaded on open — RegisterKeys streams them from
// disk — so they are checked as on-disk files instead.
func TestKeyParts(t *testing.T) {
	dir := t.TempDir()
	base := []KeysOption{WithKeyPath(dir), WithKeyID("parts"), WithKeyDim(128)}
	if err := GenerateKeys(base...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	withParts := func(parts ...KeyPart) []KeysOption {
		return append(append([]KeysOption{}, base...), WithKeyParts(parts...))
	}

	t.Run("EncOnly", func(t *testing.T) {
		k, err := OpenKeys(withParts(KeyPartEnc)...)
		if err != nil {
			t.Fatalf("OpenKeys: %v", err)
		}
		defer k.Close()
		b, err := k.EncryptFlat(vec128())
		if err != nil || len(b) == 0 {
			t.Fatalf("EncryptFlat: len=%d err=%v", len(b), err)
		}
		if _, err := k.DecryptResult([]byte{1}); !errors.Is(err, ErrKeysNotForDecrypt) {
			t.Errorf("DecryptResult err = %v, want ErrKeysNotForDecrypt", err)
		}
	})

	t.Run("SecOnly", func(t *testing.T) {
		// OpenKeys succeeding here means the Sec decryptor handle was built.
		k, err := OpenKeys(withParts(KeyPartSec)...)
		if err != nil {
			t.Fatalf("OpenKeys: %v", err)
		}
		defer k.Close()
		if _, err := k.EncryptFlat(vec128()); !errors.Is(err, ErrKeysNotForEncrypt) {
			t.Errorf("EncryptFlat err = %v, want ErrKeysNotForEncrypt", err)
		}
	})

	t.Run("AllParts", func(t *testing.T) {
		k, err := OpenKeys(base...) // no WithKeyParts → Enc + Sec on both bundles
		if err != nil {
			t.Fatalf("OpenKeys: %v", err)
		}
		defer k.Close()
		if b, err := k.EncryptFlat(vec128()); err != nil || len(b) == 0 {
			t.Fatalf("EncryptFlat: %v", err)
		}
	})

	t.Run("EvalKeysOnDisk", func(t *testing.T) {
		// RegisterKeys streams these from disk. Eval keys are kept raw (the
		// KeyPack saver's format, which the homevaluator loads via buffer; the
		// KeyManager JSON envelope cannot round-trip it) for both the RMP (root)
		// and MM (mm/) bundles.
		if _, err := os.Stat(filepath.Join(dir, evalKeyBinFile)); err != nil {
			t.Errorf("RMP eval key missing: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, mmKind.subdir, evalKeyBinFile)); err != nil {
			t.Errorf("MM eval key missing: %v", err)
		}
	})
}
