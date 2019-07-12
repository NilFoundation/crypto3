#include "fuzzers.hpp"
#include "ecc_helper.hpp"

void fuzz(const uint8_t in[], size_t len) {
    if (len > 2 * 256 / 8) {
        return;
    }
    static nil::crypto3::ec_group p256("secp256r1");
    return check_ecc_math(p256, in, len);
}
