#include "fuzzers.hpp"
#include "ecc_helper.hpp"

void fuzz(const uint8_t in[], size_t len) {
    if (len > 2 * (521 + 7) / 8) {
        return;
    }
    static nil::crypto3::ec_group p521("secp521r1");
    return check_ecc_math(p521, in, len);
}
