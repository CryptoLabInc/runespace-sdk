// Thin C ABI over evi::KeyManager (third_party/evi/include/km/KeyManager.hpp),
// implemented locally in keymanager_shim.cpp. The upstream libevi_c_api.a does
// not expose KeyManager — but libevi_crypto.a (already bundled) defines the
// C++ methods, so this shim links straight against the existing archive
// without modifying upstream evi-crypto.
//
// Every entry point is path-based and NONE-seal only: enough to read and write
// the Sec/Enc/Eval JSON key envelopes while keeping the shim surface minimal.
// AES_KEK sealing, stream variants, and SecretKey/KeyPack overloads are
// intentionally out of scope.
//
// Return codes:
//    0 success
//   -1 caller error (null pointer or empty string)
//   -2 C++ exception raised by KeyManager — call evi_km_last_error for details
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle, identical to the C API's evi_secret_key_t target struct.
struct evi_secret_key;

int evi_km_wrap_sec_key(const char *key_id, const char *in_bin_path, const char *out_json_path);
int evi_km_wrap_enc_key(const char *key_id, const char *in_bin_path, const char *out_json_path);
int evi_km_wrap_eval_key(const char *key_id, const char *in_bin_path, const char *out_json_path);

// evi_km_wrap_sec_key_from_handle envelopes a live SecretKey handle straight
// into the JSON envelope at out_json_path. KeyGenerator hands back a secret key
// in memory (unlike MultiKeyGenerator, which dumped SecKey.bin to disk), and the
// C API exposes no raw secret-key serializer — only KeyManager can persist it.
int evi_km_wrap_sec_key_from_handle(const struct evi_secret_key *seckey, const char *key_id,
                                    const char *out_json_path);

int evi_km_unwrap_sec_key(const char *in_json_path, const char *out_bin_path);
int evi_km_unwrap_enc_key(const char *in_json_path, const char *out_bin_path);
int evi_km_unwrap_eval_key(const char *in_json_path, const char *out_bin_path);

const char *evi_km_last_error(void);

#ifdef __cplusplus
}
#endif
