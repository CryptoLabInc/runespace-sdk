// Thin C ABI over evi::Encryptor::encryptRow (third_party/evi/include/EVI/
// Encryptor.hpp), implemented locally in encryptor_shim.cpp. The upstream
// libevi_c_api.a exposes only the batch encrypt path (evi_encryptor_encrypt_
// batch_with_pack); in MM mode that path returns a full transposed matrix
// (tens of MiB regardless of item count), which is unusable as a per-insert
// wire payload. encryptRow returns the compact single-row ciphertext the MM
// search pipeline actually consumes (one row per item, kilobytes each), but it
// is absent from the C API — so this shim includes Encryptor.hpp and links
// against the already-bundled libevi_crypto.a without modifying upstream evi.
//
// Return codes:
//    0 success
//   -1 caller error (null pointer or empty input)
//   -2 C++ exception raised by encryptRow — call evi_enc_last_error for details
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles, identical to the C API's evi_encryptor_t / evi_keypack_t
// target structs (defined in evi_c/internal/common_internal.hpp).
struct evi_encryptor;
struct evi_keypack;

// evi_enc_encrypt_row compact-encrypts ONE vector with evi::Encryptor::encryptRow,
// using the encryption key held in pack. enc and pack are the same handles the
// cgo provider already builds for the batch path. On success *out points to a
// malloc'd buffer of *out_size bytes that the Go caller copies out and frees.
//
//   encode_type : 0 = ITEM, 1 = QUERY (matches evi_encode_type_t / EncodeType)
//   level       : DB-scale flag — 0 = base scale, non-zero = DB scale. Stored
//                 MM items use 1; the server's make_searchable rescales to L0.
int evi_enc_encrypt_row(const struct evi_encryptor *enc, const struct evi_keypack *pack,
                        const float *vec, size_t dim, int encode_type, int level,
                        char **out, size_t *out_size);

const char *evi_enc_last_error(void);

#ifdef __cplusplus
}
#endif
