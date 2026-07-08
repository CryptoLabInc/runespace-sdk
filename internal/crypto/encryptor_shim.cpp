// C++ implementation of the encryptor shim declared in encryptor_shim.h. Sits
// in the same cgo package as cryptocgo.go so the Go toolchain compiles it
// automatically; links against the already-bundled libevi_crypto.a for the
// evi::Encryptor::encryptRow symbol the C API omits.
//
// Exception safety mirrors keymanager_shim.cpp: every entry point catches C++
// exceptions and stores the message in a thread-local buffer reachable via
// evi_enc_last_error. Go callers check the int status and pull the message
// only on failure.
#include "encryptor_shim.h"

#include "evi_c/internal/common_internal.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <optional>
#include <string>
#include <vector>

namespace {

thread_local std::string g_enc_last_error;

template <typename Fn>
int runGuarded(Fn &&fn) {
    try {
        std::forward<Fn>(fn)();
        g_enc_last_error.clear();
        return 0;
    } catch (const std::exception &e) {
        g_enc_last_error = e.what();
        return -2;
    } catch (...) {
        g_enc_last_error = "evi_enc shim: unknown C++ exception";
        return -2;
    }
}

} // namespace

extern "C" {

int evi_enc_encrypt_row(const struct evi_encryptor *enc, const struct evi_keypack *pack,
                        const float *vec, size_t dim, int encode_type, int level,
                        char **out, size_t *out_size) {
    if (enc == nullptr || pack == nullptr || vec == nullptr || out == nullptr ||
        out_size == nullptr || dim == 0) {
        g_enc_last_error = "evi_enc_encrypt_row: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        // encryptRow takes a list of rows; one row here yields one compact blob.
        std::vector<std::vector<float>> data(1, std::vector<float>(vec, vec + dim));
        std::vector<std::string> blobs = enc->impl.encryptRow(
            data, pack->impl, static_cast<evi::EncodeType>(encode_type), level, std::nullopt);
        if (blobs.empty()) {
            throw std::runtime_error("evi_enc_encrypt_row: encryptRow returned no blob");
        }
        const std::string &blob = blobs.front();
        char *buf = static_cast<char *>(std::malloc(blob.size()));
        if (buf == nullptr) {
            throw std::runtime_error("evi_enc_encrypt_row: malloc failed");
        }
        std::memcpy(buf, blob.data(), blob.size());
        *out = buf;
        *out_size = blob.size();
    });
}

const char *evi_enc_last_error(void) { return g_enc_last_error.c_str(); }

} // extern "C"
