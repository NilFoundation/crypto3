//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CAMELLIA_FUNCTIONS_CPP_HPP
#define CRYPTO3_CAMELLIA_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/camellia/basic_camellia_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t KeyBits>
                struct camellia_functions : public basic_camellia_policy<KeyBits> {
                    typedef basic_camellia_policy<KeyBits> policy_type;

                    /*
                     * We use the slow byte-wise version of F in the first and last rounds
                     * to help protect against timing attacks
                     */
                    uint64_t f_slow(uint64_t v, uint64_t K) {
                        constexpr static const uint8_t sbox[256] = {
                                0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C,
                                0xAE, 0x41, 0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E,
                                0x1D, 0x65, 0x92, 0xBD, 0x86, 0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30,
                                0xDC, 0x5F, 0x5E, 0xC5, 0x0B, 0x1A, 0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D, 0x3D,
                                0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D, 0x8B, 0x0D, 0x9A, 0x66, 0xFB, 0xCC,
                                0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99, 0xDF, 0x4C, 0xCB, 0xC2,
                                0x34, 0x7E, 0x76, 0x05, 0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7, 0x14, 0x58,
                                0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18, 0xF2, 0x22,
                                0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC,
                                0x69, 0x50, 0xAA, 0xD0, 0xA0, 0x7D, 0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95,
                                0xE0, 0xFF, 0x64, 0xD2, 0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03,
                                0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94, 0x87, 0x5C, 0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33,
                                0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2, 0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37,
                                0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E, 0xE9, 0x79, 0xA7, 0x8C,
                                0x9F, 0x6E, 0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59, 0x78, 0x98,
                                0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42, 0x88, 0xA2, 0x8D, 0xFA,
                                0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38,
                                0xF1, 0xA4, 0x40, 0x28, 0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4,
                                0x77, 0xC7, 0x80, 0x9E
                        };

                        const uint64_t x = v ^K;

                        const uint8_t t1 = sbox[policy_type::template extract_uint_t<CHAR_BIT>(x, 0)];
                        const uint8_t t2 = policy_type::template rotl<1>(
                                sbox[policy_type::template extract_uint_t<CHAR_BIT>(x, 1)]);
                        const uint8_t t3 = policy_type::template rotl<7>(
                                sbox[policy_type::template extract_uint_t<CHAR_BIT>(x, 2)]);
                        const uint8_t t4 = sbox[policy_type::template rotl<1>(
                                policy_type::template extract_uint_t<CHAR_BIT>(x, 3))];
                        const uint8_t t5 = policy_type::template rotl<1>(
                                sbox[policy_type::template extract_uint_t<CHAR_BIT>(x, 4)]);
                        const uint8_t t6 = policy_type::template rotl<7>(
                                sbox[policy_type::template extract_uint_t<CHAR_BIT>(x, 5)]);
                        const uint8_t t7 = sbox[policy_type::template rotl<1>(
                                policy_type::template extract_uint_t<CHAR_BIT>(x, 6))];
                        const uint8_t t8 = sbox[policy_type::template extract_uint_t<CHAR_BIT>(x, 7)];

                        const uint8_t y1 = t1 ^t3 ^t4 ^t6 ^t7 ^t8;
                        const uint8_t y2 = t1 ^t2 ^t4 ^t5 ^t7 ^t8;
                        const uint8_t y3 = t1 ^t2 ^t3 ^t5 ^t6 ^t8;
                        const uint8_t y4 = t2 ^t3 ^t4 ^t5 ^t6 ^t7;
                        const uint8_t y5 = t1 ^t2 ^t6 ^t7 ^t8;
                        const uint8_t y6 = t2 ^t3 ^t5 ^t7 ^t8;
                        const uint8_t y7 = t3 ^t4 ^t5 ^t6 ^t8;
                        const uint8_t y8 = t1 ^t4 ^t5 ^t6 ^t7;

                        return policy_type::template make_uint_t<64>(y1, y2, y3, y4, y5, y6, y7, y8);
                    };

                    inline uint64_t f(uint64_t v, uint64_t K) {
                        const uint64_t x = v ^K;

                        return basic_camellia_policy<KeyBits>::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                0)] ^
                               basic_camellia_policy<KeyBits>::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       1)] ^
                               basic_camellia_policy<KeyBits>::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       2)] ^
                               basic_camellia_policy<KeyBits>::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       3)] ^
                               basic_camellia_policy<KeyBits>::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       4)] ^
                               basic_camellia_policy<KeyBits>::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       5)] ^
                               basic_camellia_policy<KeyBits>::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       6)] ^
                               basic_camellia_policy<KeyBits>::sbox8[policy_type::template extract_uint_t<CHAR_BIT>(x,
                                       7)];
                    }

                    inline uint64_t fl(uint64_t v, uint64_t K) {
                        uint32_t x1 = static_cast<uint32_t>(v >> 32);
                        uint32_t x2 = static_cast<uint32_t>(v & 0xFFFFFFFF);

                        const uint32_t k1 = static_cast<uint32_t>(K >> 32);
                        const uint32_t k2 = static_cast<uint32_t>(K & 0xFFFFFFFF);

                        x2 ^= policy_type::template rotl<1>(x1 & k1);
                        x1 ^= (x2 | k2);

                        return ((static_cast<uint64_t>(x1) << 32) | x2);
                    }

                    inline uint64_t flinv(uint64_t v, uint64_t K) {
                        uint32_t x1 = static_cast<uint32_t>(v >> 32);
                        uint32_t x2 = static_cast<uint32_t>(v & 0xFFFFFFFF);

                        const uint32_t k1 = static_cast<uint32_t>(K >> 32);
                        const uint32_t k2 = static_cast<uint32_t>(K & 0xFFFFFFFF);

                        x1 ^= (x2 | k2);
                        x2 ^= policy_type::template rotl<1>(x1 & k1);

                        return ((static_cast<uint64_t>(x1) << 32) | x2);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_CAMELLIA_FUNCTIONS_CPP_HPP
