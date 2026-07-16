// Package crypto's cgo provider binds the upstream C API in
// third_party/evi/include/evi_c/*.h to the Provider interface. The surface
// is intentionally narrow — only the functions the active (IP-preset,
// NONE-seal) path exercises are wired up:
//
//	Context     evi_context_create / _destroy
//	KeyGen      evi_keygenerator_create + _generate_secret_key +
//	            _generate_public_keys; keypack_save_enc_key / _eval_key for the
//	            public material, and the KeyManager shim to persist the secret key
//	Encryptor   evi_keypack_create_from_path + evi_encryptor_create +
//	            evi_encryptor_encrypt_batch_with_pack +
//	            evi_query_serialize_to_string + evi_query_array_destroy
//	Decryptor   evi_secret_key_create_from_path + evi_decryptor_create +
//	            evi_search_result_deserialize_from_string +
//	            evi_decryptor_decrypt_search_result_with_seckey +
//	            evi_message_{data,size,destroy}
//
// Every other C API symbol is intentionally untouched. Keys are loaded
// from disk (not from in-memory bytes) because the C API lacks stream
// variants for KeyPack / SecretKey.
//
// In addition to the upstream C API, this package ships a local C-ABI
// shim (keymanager_shim.{h,cpp}) that wraps evi::KeyManager directly from
// libevi_crypto.a — the upstream libevi_c_api.a omits KeyManager, so
// Wrap/UnwrapSecKey/EncKey/EvalKey would not reach cgo without this layer.
// The shim is path-based, NONE-seal only, and used by keys.go to produce
// and consume the JSON key envelopes.
package crypto

/*
// OpenSSL note: libevi_crypto.a's AES.cpp.o + Utils.cpp.o reference BIO_*,
// EVP_* and RAND_* symbols. These .o members are pulled in transitively
// by evi_seal_info_create (which KeyGenerator and Decryptor both call,
// even at seal_mode=NONE), so -lssl -lcrypto are required at link time
// regardless of whether the SDK ever constructs a non-NONE seal. On
// macOS/arm64 the openssl@3 prefix is the Apple Silicon Homebrew path
// (/opt/homebrew); the C++ runtime (-lc++) is not listed because the Go
// toolchain adds it automatically for packages that compile C++ (the
// .cpp shims here). Linux assumes system libssl-dev. Windows assumes
// MSYS2 mingw-w64-x86_64-openssl.
// EVI_STATIC tells EVI/Export.hpp to leave EVI_API empty on all
// platforms. We link against the bundled static archives
// (libevi_c_api.a, libevi_crypto.a), so Windows must not treat the
// API-annotated class/function declarations in km/KeyManager.hpp as
// __declspec(dllimport) — otherwise mingw emits __imp_<mangled>
// references that the static archive does not provide.
#cgo CPPFLAGS: -I${SRCDIR}/../../third_party/evi/include -DEVI_STATIC
#cgo CXXFLAGS: -std=c++17
#cgo darwin,arm64  LDFLAGS: -L${SRCDIR}/../../third_party/evi/darwin_arm64/lib  -levi_c_api -levi_crypto -ldeb -lalea -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lm
#cgo linux,amd64   LDFLAGS: -L${SRCDIR}/../../third_party/evi/linux_amd64/lib   -levi_c_api -levi_crypto -ldeb -lalea -lssl -lcrypto -lstdc++ -lm
#cgo linux,arm64   LDFLAGS: -L${SRCDIR}/../../third_party/evi/linux_arm64/lib   -levi_c_api -levi_crypto -ldeb -lalea -lssl -lcrypto -lstdc++ -lm
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/../../third_party/evi/windows_amd64/lib -levi_c_api -levi_crypto -ldeb -lalea -lssl -lcrypto -lstdc++ -lm -lws2_32 -lcrypt32

#include <stdlib.h>
#include "c_api.h"
#include "keymanager_shim.h"
#include "encryptor_shim.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// Key file names. Generate writes the Enc/Eval material as raw .bin and the
// secret key as its JSON envelope (no raw secret-key serializer is exposed);
// NewDecryptor loads the secret key from the staged SecKey.bin that keys.go
// materialises from that envelope.
const (
	cgoEncKeyFile     = "EncKey.bin"
	cgoEvalKeyFile    = "EvalKey.bin"
	cgoSecKeyFile     = "SecKey.bin"
	cgoSecKeyJSONFile = "SecKey.json"
)

// --- error helpers ---------------------------------------------------------

// pinThread locks the goroutine to its OS thread for a cgo sequence. The evi C
// API and the local shims report failures via a thread-local last-error buffer
// read by a SEPARATE cgo call (wrapEviError/kmShimError/encShimError); without
// pinning, a goroutine reschedule between the failing call and that read would
// return another thread's (empty or stale) message. Use: defer pinThread()().
func pinThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

func wrapEviError(op string, st C.evi_status_t) error {
	msg := C.GoString(C.evi_last_error_message())
	if msg == "" {
		return fmt.Errorf("runespace/crypto: %s: status=%d", op, int(st))
	}
	return fmt.Errorf("runespace/crypto: %s: %s (status=%d)", op, msg, int(st))
}

// --- key manager shim ------------------------------------------------------
//
// The upstream libevi_c_api.a does not expose evi::KeyManager. Rather than
// patch upstream + rebuild every platform archive, internal/crypto/
// ships its own thin C-ABI shim (keymanager_shim.{h,cpp}) that includes
// km/KeyManager.hpp and links against the already-bundled libevi_crypto.a.
// Wrap/Unwrap below are the Go side of that shim, exposed so keys.go can
// convert between the raw .bin files libevi writes and the JSON envelopes
// (SecKey.json / EncKey.json / EvalKey.json) for cross-SDK compat. NONE-seal
// only — AES_KEK sealing is not wired.

func kmShimError(op string, rc C.int) error {
	msg := C.GoString(C.evi_km_last_error())
	switch rc {
	case 0:
		return nil
	case -1:
		if msg == "" {
			return fmt.Errorf("runespace/crypto: %s: invalid argument", op)
		}
		return fmt.Errorf("runespace/crypto: %s: %s", op, msg)
	default:
		if msg == "" {
			return fmt.Errorf("runespace/crypto: %s: KeyManager exception (rc=%d)", op, int(rc))
		}
		return fmt.Errorf("runespace/crypto: %s: %s", op, msg)
	}
}

// encShimError maps the encryptor shim return code + thread-local message into
// a Go error, mirroring kmShimError.
func encShimError(op string, rc C.int) error {
	msg := C.GoString(C.evi_enc_last_error())
	switch rc {
	case 0:
		return nil
	case -1:
		if msg == "" {
			return fmt.Errorf("runespace/crypto: %s: invalid argument", op)
		}
		return fmt.Errorf("runespace/crypto: %s: %s", op, msg)
	default:
		if msg == "" {
			return fmt.Errorf("runespace/crypto: %s: encryptor shim exception (rc=%d)", op, int(rc))
		}
		return fmt.Errorf("runespace/crypto: %s: %s", op, msg)
	}
}

// WrapSecKey envelopes the raw libevi SecKey.bin at binPath into the
// JSON envelope at jsonPath, tagging it with keyID.
func WrapSecKey(keyID, binPath, jsonPath string) error {
	defer pinThread()()
	cID := C.CString(keyID)
	cIn := C.CString(binPath)
	cOut := C.CString(jsonPath)
	defer C.free(unsafe.Pointer(cID))
	defer C.free(unsafe.Pointer(cIn))
	defer C.free(unsafe.Pointer(cOut))
	return kmShimError("evi_km_wrap_sec_key", C.evi_km_wrap_sec_key(cID, cIn, cOut))
}

// WrapEncKey is the EncKey counterpart of WrapSecKey.
func WrapEncKey(keyID, binPath, jsonPath string) error {
	defer pinThread()()
	cID := C.CString(keyID)
	cIn := C.CString(binPath)
	cOut := C.CString(jsonPath)
	defer C.free(unsafe.Pointer(cID))
	defer C.free(unsafe.Pointer(cIn))
	defer C.free(unsafe.Pointer(cOut))
	return kmShimError("evi_km_wrap_enc_key", C.evi_km_wrap_enc_key(cID, cIn, cOut))
}

// WrapEvalKey is the EvalKey counterpart of WrapSecKey.
func WrapEvalKey(keyID, binPath, jsonPath string) error {
	defer pinThread()()
	cID := C.CString(keyID)
	cIn := C.CString(binPath)
	cOut := C.CString(jsonPath)
	defer C.free(unsafe.Pointer(cID))
	defer C.free(unsafe.Pointer(cIn))
	defer C.free(unsafe.Pointer(cOut))
	return kmShimError("evi_km_wrap_eval_key", C.evi_km_wrap_eval_key(cID, cIn, cOut))
}

// UnwrapSecKey extracts the raw SecKey.bin payload from a JSON envelope. NONE
// seal only; sealed bundles are rejected by the underlying KeyManager.
func UnwrapSecKey(jsonPath, binPath string) error {
	defer pinThread()()
	cIn := C.CString(jsonPath)
	cOut := C.CString(binPath)
	defer C.free(unsafe.Pointer(cIn))
	defer C.free(unsafe.Pointer(cOut))
	return kmShimError("evi_km_unwrap_sec_key", C.evi_km_unwrap_sec_key(cIn, cOut))
}

// UnwrapEncKey is the EncKey counterpart of UnwrapSecKey.
func UnwrapEncKey(jsonPath, binPath string) error {
	defer pinThread()()
	cIn := C.CString(jsonPath)
	cOut := C.CString(binPath)
	defer C.free(unsafe.Pointer(cIn))
	defer C.free(unsafe.Pointer(cOut))
	return kmShimError("evi_km_unwrap_enc_key", C.evi_km_unwrap_enc_key(cIn, cOut))
}

// UnwrapEvalKey is the EvalKey counterpart of UnwrapSecKey.
func UnwrapEvalKey(jsonPath, binPath string) error {
	defer pinThread()()
	cIn := C.CString(jsonPath)
	cOut := C.CString(binPath)
	defer C.free(unsafe.Pointer(cIn))
	defer C.free(unsafe.Pointer(cOut))
	return kmShimError("evi_km_unwrap_eval_key", C.evi_km_unwrap_eval_key(cIn, cOut))
}

// --- context ---------------------------------------------------------------

type cgoContext struct {
	c *C.evi_context_t
}

func (c *cgoContext) Close() error {
	if c.c != nil {
		C.evi_context_destroy(c.c)
		c.c = nil
	}
	return nil
}

type cgoProvider struct{}

func (cgoProvider) NewCKKSContext(params CKKSParams) (CKKSContext, error) {
	defer pinThread()()
	if len(params.DimList) == 0 {
		return nil, errors.New("runespace/crypto: CKKSParams.DimList must contain at least one dim")
	}
	preset, err := presetToEnum(params.Preset)
	if err != nil {
		return nil, err
	}
	evalMode, err := evalModeToEnum(params.EvalMode)
	if err != nil {
		return nil, err
	}

	var ctx *C.evi_context_t
	st := C.evi_context_create(
		C.evi_parameter_preset_t(preset),
		C.evi_device_type_t(C.EVI_DEVICE_TYPE_CPU),
		C.uint64_t(params.DimList[0]),
		C.evi_eval_mode_t(evalMode),
		nil,
		&ctx,
	)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_context_create", st)
	}
	c := &cgoContext{c: ctx}
	runtime.SetFinalizer(c, func(c *cgoContext) { _ = c.Close() })
	return c, nil
}

// --- key generator (KeyGenerator + seal_info NONE) ------------------------

type cgoKeyGen struct {
	params KeyGenParams
}

func (cgoProvider) NewKeyGenerator(p KeyGenParams) (KeyGenerator, error) {
	return &cgoKeyGen{params: p}, nil
}

// Generate produces one CKKS key trio under KeyPath: EncKey.bin and EvalKey.bin
// (raw, via the KeyPack savers) plus SecKey.json (the KeyManager envelope).
//
// It uses KeyGenerator (generate_secret_key + generate_public_keys), not
// MultiKeyGenerator. MultiKeyGenerator's EvalKey is unusable for an RMP/PC
// search — the homomorphic inner products come back unbounded instead of in
// [0,1] — whereas the KeyGenerator eval key scores a self-match at ~1.0. The
// trade-off is that KeyGenerator keeps the secret key in memory rather than
// dumping SecKey.bin to disk, so it is persisted through the KeyManager shim.
func (g *cgoKeyGen) Generate() error {
	defer pinThread()()
	if g.params.KeyPath == "" {
		return errors.New("runespace/crypto: KeyPath required")
	}
	if len(g.params.DimList) != 1 {
		return fmt.Errorf("runespace/crypto: KeyGenerator needs exactly one dim, got %d", len(g.params.DimList))
	}
	if g.params.KeyID == "" {
		return errors.New("runespace/crypto: KeyID required to envelope the secret key")
	}
	preset, err := presetToEnum(g.params.Preset)
	if err != nil {
		return err
	}
	evalMode, err := evalModeToEnum(g.params.EvalMode)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(g.params.KeyPath, 0o755); err != nil {
		return fmt.Errorf("runespace/crypto: mkdir key path: %w", err)
	}
	// Reject non-empty key dirs to keep Generate's no-overwrite behaviour
	// obvious to the caller. The higher-level runespace.GenerateKeys uses
	// KeysExist as the primary guard, but this second check catches stale
	// partial state.
	if empty, err := isEmptyDir(g.params.KeyPath); err != nil {
		return err
	} else if !empty {
		return fmt.Errorf("runespace/crypto: key path %q is not empty", g.params.KeyPath)
	}

	var ctx *C.evi_context_t
	st := C.evi_context_create(
		C.evi_parameter_preset_t(preset),
		C.evi_device_type_t(C.EVI_DEVICE_TYPE_CPU),
		C.uint64_t(g.params.DimList[0]),
		C.evi_eval_mode_t(evalMode),
		nil,
		&ctx,
	)
	if st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_context_create", st)
	}
	defer C.evi_context_destroy(ctx)

	var pack *C.evi_keypack_t
	if st := C.evi_keypack_create(ctx, &pack); st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_keypack_create", st)
	}
	defer C.evi_keypack_destroy(pack)

	var gen *C.evi_keygenerator_t
	if st := C.evi_keygenerator_create(ctx, pack, &gen); st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_keygenerator_create", st)
	}
	defer C.evi_keygenerator_destroy(gen)

	var sk *C.evi_secret_key_t
	if st := C.evi_keygenerator_generate_secret_key(gen, &sk); st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_keygenerator_generate_secret_key", st)
	}
	defer C.evi_secret_key_destroy(sk)
	if st := C.evi_keygenerator_generate_public_keys(gen, sk); st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_keygenerator_generate_public_keys", st)
	}

	encPath := C.CString(filepath.Join(g.params.KeyPath, cgoEncKeyFile))
	defer C.free(unsafe.Pointer(encPath))
	if st := C.evi_keypack_save_enc_key(pack, encPath); st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_keypack_save_enc_key", st)
	}
	evalPath := C.CString(filepath.Join(g.params.KeyPath, cgoEvalKeyFile))
	defer C.free(unsafe.Pointer(evalPath))
	if st := C.evi_keypack_save_eval_key(pack, evalPath); st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_keypack_save_eval_key", st)
	}

	// No raw secret-key serializer exists in the C API; the KeyManager shim
	// envelopes the live handle straight into SecKey.json.
	secJSON := C.CString(filepath.Join(g.params.KeyPath, cgoSecKeyJSONFile))
	defer C.free(unsafe.Pointer(secJSON))
	cKeyID := C.CString(g.params.KeyID)
	defer C.free(unsafe.Pointer(cKeyID))
	if rc := C.evi_km_wrap_sec_key_from_handle(sk, cKeyID, secJSON); rc != 0 {
		return kmShimError("evi_km_wrap_sec_key_from_handle", rc)
	}
	return nil
}

// --- encryptor -------------------------------------------------------------

type cgoEncryptor struct {
	// mu guards enc/pack against Close freeing the C++ objects while an
	// EncryptSingle/EncryptRow call still holds them: encrypt takes RLock for
	// its whole cgo call, Close takes the exclusive Lock. Without this, a
	// concurrent Close (including the GC finalizer) is a native use-after-free.
	mu   sync.RWMutex
	enc  *C.evi_encryptor_t
	pack *C.evi_keypack_t
}

func (e *cgoEncryptor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enc != nil {
		C.evi_encryptor_destroy(e.enc)
		e.enc = nil
	}
	if e.pack != nil {
		C.evi_keypack_destroy(e.pack)
		e.pack = nil
	}
	return nil
}

func (cgoProvider) NewEncryptor(ctxIface CKKSContext, keyDir string) (Encryptor, error) {
	defer pinThread()()
	cctx, ok := ctxIface.(*cgoContext)
	if !ok || cctx.c == nil {
		return nil, errors.New("runespace/crypto: NewEncryptor requires an open cgo context")
	}

	cKeyDir := C.CString(keyDir)
	defer C.free(unsafe.Pointer(cKeyDir))

	// Encrypt only consumes EncKey from the KeyPack. Skip the
	// _create_from_path overload — at EvalMode != MM it would also pull in
	// the (much larger) EvalKey via deserializeEvalKey + temp dump dir,
	// which the client-side encrypt path never touches.
	var pack *C.evi_keypack_t
	st := C.evi_keypack_create(cctx.c, &pack)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_keypack_create", st)
	}
	st = C.evi_keypack_load_enc_key(pack, cKeyDir)
	if st != C.EVI_STATUS_SUCCESS {
		C.evi_keypack_destroy(pack)
		return nil, wrapEviError("evi_keypack_load_enc_key", st)
	}

	var enc *C.evi_encryptor_t
	st = C.evi_encryptor_create(cctx.c, &enc)
	// cctx has a GC finalizer that frees cctx.c; keep it reachable until the
	// last cgo call that reads cctx.c returns.
	runtime.KeepAlive(cctx)
	if st != C.EVI_STATUS_SUCCESS {
		C.evi_keypack_destroy(pack)
		return nil, wrapEviError("evi_encryptor_create", st)
	}

	e := &cgoEncryptor{enc: enc, pack: pack}
	runtime.SetFinalizer(e, func(e *cgoEncryptor) { _ = e.Close() })
	return e, nil
}

func (e *cgoEncryptor) EncryptSingle(vec []float32, encodeType string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	defer pinThread()()
	if e.enc == nil || e.pack == nil {
		return nil, errors.New("runespace/crypto: encryptor closed")
	}
	dim := len(vec)
	if dim == 0 {
		return nil, errors.New("runespace/crypto: vector dim must be > 0")
	}
	encTypeInt, err := encodeTypeToEnum(encodeType)
	if err != nil {
		return nil, err
	}

	row := (*C.float)(C.malloc(C.size_t(dim) * C.size_t(unsafe.Sizeof(C.float(0)))))
	if row == nil {
		return nil, errors.New("runespace/crypto: malloc failed")
	}
	defer C.free(unsafe.Pointer(row))
	rowSlice := unsafe.Slice(row, dim)
	for j, f := range vec {
		rowSlice[j] = C.float(f)
	}

	// One item via the batch-with-pack path with a single-element batch: evi
	// requires items to go through the batch packing even one at a time, and the
	// server appends with the matching evi_index_batch_append.
	ptrArr := (**C.float)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0)))))
	if ptrArr == nil {
		return nil, errors.New("runespace/crypto: malloc failed")
	}
	defer C.free(unsafe.Pointer(ptrArr))
	unsafe.Slice(ptrArr, 1)[0] = row

	var outQueries **C.evi_query_t
	var outCount C.size_t
	st := C.evi_encryptor_encrypt_batch_with_pack(
		e.enc, e.pack,
		ptrArr,
		C.size_t(dim),
		1, // single item, batch packing
		C.evi_encode_type_t(encTypeInt),
		0,   // level = 0 (qf disabled)
		nil, // scale = NULL → upstream default
		&outQueries,
		&outCount,
	)
	// e has a GC finalizer that frees e.enc/e.pack; keep it reachable until the
	// cgo call that reads those pointers returns (belt to the RLock's suspenders).
	runtime.KeepAlive(e)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_encryptor_encrypt_batch_with_pack", st)
	}
	defer C.evi_query_array_destroy(outQueries, outCount)
	if int(outCount) < 1 {
		return nil, errors.New("runespace/crypto: batch encrypt returned no query")
	}
	q := unsafe.Slice(outQueries, int(outCount))[0]

	var data *C.char
	var size C.size_t
	if st := C.evi_query_serialize_to_string(q, &data, &size); st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_query_serialize_to_string", st)
	}
	defer C.free(unsafe.Pointer(data))
	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// EncryptRow is the MM item path: it compact-encrypts one vector through
// evi::Encryptor::encryptRow (via encryptor_shim) into a single coefficient-
// domain row ciphertext. This is the wire form the clustered (MM) search
// pipeline consumes — the server later transposes and merges these rows at
// compaction. EncryptSingle's batch-with-pack route is RMP-only: in MM mode it
// returns a full transposed matrix (tens of MiB) unsuitable per insert, so the
// two item routes are deliberately split. encodeType is "item" for stored
// payloads; level 1 selects the DB scale that make_searchable rescales to L0.
func (e *cgoEncryptor) EncryptRow(vec []float32, encodeType string, level int) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	defer pinThread()()
	if e.enc == nil || e.pack == nil {
		return nil, errors.New("runespace/crypto: encryptor closed")
	}
	dim := len(vec)
	if dim == 0 {
		return nil, errors.New("runespace/crypto: vector dim must be > 0")
	}
	encTypeInt, err := encodeTypeToEnum(encodeType)
	if err != nil {
		return nil, err
	}

	row := (*C.float)(C.malloc(C.size_t(dim) * C.size_t(unsafe.Sizeof(C.float(0)))))
	if row == nil {
		return nil, errors.New("runespace/crypto: malloc failed")
	}
	defer C.free(unsafe.Pointer(row))
	rowSlice := unsafe.Slice(row, dim)
	for j, f := range vec {
		rowSlice[j] = C.float(f)
	}

	var out *C.char
	var outSize C.size_t
	rc := C.evi_enc_encrypt_row(
		e.enc, e.pack,
		row, C.size_t(dim),
		C.int(encTypeInt), C.int(level),
		&out, &outSize,
	)
	runtime.KeepAlive(e) // see EncryptSingle: keep e.enc/e.pack alive across the cgo call
	if rc != 0 {
		return nil, encShimError("evi_enc_encrypt_row", rc)
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outSize)), nil
}

// --- decryptor -------------------------------------------------------------

type cgoDecryptor struct {
	// mu guards dec/sk the same way cgoEncryptor.mu guards enc/pack: a decrypt
	// holds RLock for its whole cgo call so a concurrent Close (or the GC
	// finalizer) cannot free the secret-key/decryptor mid-call.
	mu  sync.RWMutex
	dec *C.evi_decryptor_t
	sk  *C.evi_secret_key_t
}

func (d *cgoDecryptor) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dec != nil {
		C.evi_decryptor_destroy(d.dec)
		d.dec = nil
	}
	if d.sk != nil {
		C.evi_secret_key_destroy(d.sk)
		d.sk = nil
	}
	return nil
}

func (cgoProvider) NewDecryptor(ctxIface CKKSContext, keyDir string) (Decryptor, error) {
	defer pinThread()()
	cctx, ok := ctxIface.(*cgoContext)
	if !ok || cctx.c == nil {
		return nil, errors.New("runespace/crypto: NewDecryptor requires an open cgo context")
	}

	secPath := filepath.Join(keyDir, cgoSecKeyFile)
	cPath := C.CString(secPath)
	defer C.free(unsafe.Pointer(cPath))

	var sk *C.evi_secret_key_t
	st := C.evi_secret_key_create_from_path(cPath, &sk)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_secret_key_create_from_path", st)
	}

	var dec *C.evi_decryptor_t
	st = C.evi_decryptor_create(cctx.c, &dec)
	runtime.KeepAlive(cctx) // see NewEncryptor: keep the context alive across the cgo call
	if st != C.EVI_STATUS_SUCCESS {
		C.evi_secret_key_destroy(sk)
		return nil, wrapEviError("evi_decryptor_create", st)
	}

	d := &cgoDecryptor{dec: dec, sk: sk}
	runtime.SetFinalizer(d, func(d *cgoDecryptor) { _ = d.Close() })
	return d, nil
}

// DecryptSearchResult decrypts one serialized evi search_result blob — the
// RuneSpaceService Search response `result` — into its per-slot score vector.
// The engine is blind and returns a single packed ciphertext holding every
// live item's inner-product score; scores[i] is the score for index slot i.
// The slot->id mapping is the caller's responsibility (the server returns no
// ids — see runespace.proto SearchResponse).
func (d *cgoDecryptor) DecryptSearchResult(result []byte) ([]float64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	defer pinThread()()
	if d.dec == nil || d.sk == nil {
		return nil, errors.New("runespace/crypto: decryptor closed")
	}
	if len(result) == 0 {
		return nil, errors.New("runespace/crypto: empty search result")
	}
	cData := (*C.char)(unsafe.Pointer(&result[0]))

	var sr *C.evi_search_result_t
	st := C.evi_search_result_deserialize_from_string(cData, C.size_t(len(result)), &sr)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_search_result_deserialize_from_string", st)
	}
	defer C.evi_search_result_destroy(sr)

	var msg *C.evi_message_t
	st = C.evi_decryptor_decrypt_search_result_with_seckey(d.dec, sr, d.sk, 1, nil, &msg)
	runtime.KeepAlive(d) // keep d.dec/d.sk alive across the cgo call
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_decryptor_decrypt_search_result_with_seckey", st)
	}
	defer C.evi_message_destroy(msg)

	var itemCount C.uint32_t
	st = C.evi_search_result_get_item_count(sr, &itemCount)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_search_result_get_item_count", st)
	}

	msgSize := int(C.evi_message_size(msg))
	n := int(itemCount)
	if n > msgSize {
		n = msgSize
	}
	scores := make([]float64, n)
	if n > 0 {
		src := C.evi_message_data(msg)
		values := unsafe.Slice(src, n)
		for j, v := range values {
			scores[j] = float64(v)
		}
	}
	return scores, nil
}

// --- misc ------------------------------------------------------------------

func isEmptyDir(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}
