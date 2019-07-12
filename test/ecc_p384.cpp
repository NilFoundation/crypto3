#include "fuzzers.hpp"
#include "ecc_helper.hpp"

void fuzz(const uint8_t in[], size_t len) {
    if (len > 2 * 384 / 8) {
        return;
    }
    static nil::crypto3::ec_group p384("secp384r1");
    return check_ecc_math(p384, in, len);
}
