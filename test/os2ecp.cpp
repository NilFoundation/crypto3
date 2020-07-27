#include "fuzzers.h"
#include <nil/crypto3/pubkey/ec_group/ec_group.hpp>
#include <nil/crypto3/pubkey/ec_group/point_gfp.h>

namespace {

    void check_os2ecp(const nil::crypto3::ec_group &group, const uint8_t in[], size_t len) {
        try {
            nil::crypto3::point_gfp point = group.os2ecp(in, len);
        } catch (nil::crypto3::Exception &e) {
        }
    }

}    // namespace

void fuzz(const uint8_t in[], size_t len) {
    if (len >= 256) {
        return;
    }

    static nil::crypto3::ec_group p192("secp192r1");
    static nil::crypto3::ec_group p224("secp224r1");
    static nil::crypto3::ec_group p256("secp256r1");
    static nil::crypto3::ec_group p384("secp384r1");
    static nil::crypto3::ec_group p521("secp521r1");
    static nil::crypto3::ec_group bp256("brainpool256r1");
    static nil::crypto3::ec_group bp512("brainpool512r1");

    check_os2ecp(p192, in, len);
    check_os2ecp(p224, in, len);
    check_os2ecp(p256, in, len);
    check_os2ecp(p384, in, len);
    check_os2ecp(p521, in, len);
    check_os2ecp(p521, in, len);
    check_os2ecp(bp256, in, len);
    check_os2ecp(bp512, in, len);
}
