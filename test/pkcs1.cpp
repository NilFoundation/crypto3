#include "fuzzers.h"

#include <nil/crypto3/pkpad/eme_pkcs1/eme_pkcs.hpp>

#include <nil/crypto3/codec/hex.hpp>

namespace {

    std::vector<uint8_t> simple_pkcs1_unpad(const uint8_t in[], size_t len) {
        if (len < 10) {
            throw nil::crypto3::decoding_error("bad len");
        }

        if (in[0] != 0 || in[1] != 2) {
            throw nil::crypto3::decoding_error("bad header field");
        }

        for (size_t i = 2; i < len; ++i) {
            if (in[i] == 0) {
                if (i < 10) { // at least 8 padding bytes required
                    throw nil::crypto3::decoding_error("insufficient padding bytes");
                }
                return std::vector<uint8_t>(in + i + 1, in + len);
            }
        }

        throw nil::crypto3::decoding_error("delim not found");
    }

}

void fuzz(const uint8_t in[], size_t len) {
    static nil::crypto3::EME_PKCS1v15 pkcs1;

    nil::crypto3::secure_vector<uint8_t> lib_result;
    std::vector<uint8_t> ref_result;
    bool lib_rejected = false, ref_rejected = false;

    try {
        uint8_t valid_mask = 0;
        nil::crypto3::secure_vector<uint8_t> decoded = (static_cast<nil::crypto3::EME *>(&pkcs1))->unpad(valid_mask, in,
                                                                                                         len);

        if (valid_mask == 0) {
            lib_rejected = true;
        } else if (valid_mask == 0xFF) {
            lib_rejected = false;
        } else
            FUZZER_WRITE_AND_CRASH("Invalid valid_mask from unpad");
    } catch (nil::crypto3::decoding_error &) {
        lib_rejected = true;
    }

    try {
        ref_result = simple_pkcs1_unpad(in, len);
    } catch (nil::crypto3::decoding_error &e) {
        ref_rejected = true;
    }

    if (lib_rejected && !ref_rejected) {
        FUZZER_WRITE_AND_CRASH("Library rejected input accepted by ref " << nil::crypto3::hex_encode(ref_result));
    } else if (ref_rejected && !lib_rejected) {
        FUZZER_WRITE_AND_CRASH("Library accepted input rejected by ref " << nil::crypto3::hex_encode(lib_result));
    }
    // otherwise the two implementations agree
}
