#include "keys.h"
static const char CTX[crypto_kdf_CONTEXTBYTES] = "tglmkdf";
void derive_subkey(uint8_t out[32], uint64_t id, const uint8_t K[32]) {
    crypto_kdf_derive_from_key(out, 32, id, CTX, K);
}
