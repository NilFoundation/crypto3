//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DES_FUNCTIONS_HPP
#define CRYPTO3_DES_FUNCTIONS_HPP

#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/des/des_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<typename PolicyType>
                struct des_functions : public PolicyType {
                protected:
                    typedef PolicyType policy_type;

                public:
                    typedef typename policy_type::byte_type byte_type;
                    typedef typename policy_type::word_type word_type;

                    typedef typename policy_type::block_type block_type;

                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    inline static void ip(word_type &L, word_type &R, const block_type &block) {
                        L = boost::endian::native_to_big(block[0]);
                        R = boost::endian::native_to_big(block[1]);

                        word_type T;
                        R = policy_type::template rotl<4>(R);
                        T = (L ^ R) & 0xF0F0F0F0;
                        L ^= T;
                        R = policy_type::template rotr<20>(R ^ T);
                        T = (L ^ R) & 0xFFFF0000;
                        L ^= T;
                        R = policy_type::template rotr<18>(R ^ T);
                        T = (L ^ R) & 0x33333333;
                        L ^= T;
                        R = policy_type::template rotr<6>(R ^ T);
                        T = (L ^ R) & 0x00FF00FF;
                        L ^= T;
                        R = policy_type::template rotl<9>(R ^ T);
                        T = (L ^ R) & 0xAAAAAAAA;
                        L = policy_type::template rotl<1>(L ^ T);
                        R ^= T;
                    }

                    inline static void fp(word_type L, word_type R, block_type &block) {
                        // FP sequence by Wei Dai, taken from public domain Crypto++
                        word_type T;

                        R = policy_type::template rotr<1>(R);
                        T = (L ^ R) & 0xAAAAAAAA;
                        R ^= T;
                        L = policy_type::template rotr<9>(L ^ T);
                        T = (L ^ R) & 0x00FF00FF;
                        R ^= T;
                        L = policy_type::template rotl<6>(L ^ T);
                        T = (L ^ R) & 0x33333333;
                        R ^= T;
                        L = policy_type::template rotl<18>(L ^ T);
                        T = (L ^ R) & 0xFFFF0000;
                        R ^= T;
                        L = policy_type::template rotl<20>(L ^ T);
                        T = (L ^ R) & 0xF0F0F0F0;
                        R ^= T;
                        L = policy_type::template rotr<4>(L ^ T);

                        block = {boost::endian::native_to_big(R), boost::endian::native_to_big(L)};
                    }

                    inline static void des_key_schedule(key_schedule_type &round_key, const key_type &key) {

                        constexpr static const std::array<byte_type, 16> ROT = {1, 1, 2, 2, 2, 2, 2, 2,
                                                                                1, 2, 2, 2, 2, 2, 2, 1};

                        word_type C = ((key[7] & 0x80) << 20) | ((key[6] & 0x80) << 19) | ((key[5] & 0x80) << 18) |
                                      ((key[4] & 0x80) << 17) | ((key[3] & 0x80) << 16) | ((key[2] & 0x80) << 15) |
                                      ((key[1] & 0x80) << 14) | ((key[0] & 0x80) << 13) | ((key[7] & 0x40) << 13) |
                                      ((key[6] & 0x40) << 12) | ((key[5] & 0x40) << 11) | ((key[4] & 0x40) << 10) |
                                      ((key[3] & 0x40) << 9) | ((key[2] & 0x40) << 8) | ((key[1] & 0x40) << 7) |
                                      ((key[0] & 0x40) << 6) | ((key[7] & 0x20) << 6) | ((key[6] & 0x20) << 5) |
                                      ((key[5] & 0x20) << 4) | ((key[4] & 0x20) << 3) | ((key[3] & 0x20) << 2) |
                                      ((key[2] & 0x20) << 1) | ((key[1] & 0x20)) | ((key[0] & 0x20) >> 1) |
                                      ((key[7] & 0x10) >> 1) | ((key[6] & 0x10) >> 2) | ((key[5] & 0x10) >> 3) |
                                      ((key[4] & 0x10) >> 4);
                        word_type D = ((key[7] & 0x02) << 26) | ((key[6] & 0x02) << 25) | ((key[5] & 0x02) << 24) |
                                      ((key[4] & 0x02) << 23) | ((key[3] & 0x02) << 22) | ((key[2] & 0x02) << 21) |
                                      ((key[1] & 0x02) << 20) | ((key[0] & 0x02) << 19) | ((key[7] & 0x04) << 17) |
                                      ((key[6] & 0x04) << 16) | ((key[5] & 0x04) << 15) | ((key[4] & 0x04) << 14) |
                                      ((key[3] & 0x04) << 13) | ((key[2] & 0x04) << 12) | ((key[1] & 0x04) << 11) |
                                      ((key[0] & 0x04) << 10) | ((key[7] & 0x08) << 8) | ((key[6] & 0x08) << 7) |
                                      ((key[5] & 0x08) << 6) | ((key[4] & 0x08) << 5) | ((key[3] & 0x08) << 4) |
                                      ((key[2] & 0x08) << 3) | ((key[1] & 0x08) << 2) | ((key[0] & 0x08) << 1) |
                                      ((key[3] & 0x10) >> 1) | ((key[2] & 0x10) >> 2) | ((key[1] & 0x10) >> 3) |
                                      ((key[0] & 0x10) >> 4);

                        for (size_t i = 0; i != 16; ++i) {
                            C = ((C << ROT[i]) | (C >> (28 - ROT[i]))) & 0x0FFFFFFF;
                            D = ((D << ROT[i]) | (D >> (28 - ROT[i]))) & 0x0FFFFFFF;
                            round_key[2 * i] =
                                ((C & 0x00000010) << 22) | ((C & 0x00000800) << 17) | ((C & 0x00000020) << 16) |
                                ((C & 0x00004004) << 15) | ((C & 0x00000200) << 11) | ((C & 0x00020000) << 10) |
                                ((C & 0x01000000) >> 6) | ((C & 0x00100000) >> 4) | ((C & 0x00010000) << 3) |
                                ((C & 0x08000000) >> 2) | ((C & 0x00800000) << 1) | ((D & 0x00000010) << 8) |
                                ((D & 0x00000002) << 7) | ((D & 0x00000001) << 2) | ((D & 0x00000200)) |
                                ((D & 0x00008000) >> 2) | ((D & 0x00000088) >> 3) | ((D & 0x00001000) >> 7) |
                                ((D & 0x00080000) >> 9) | ((D & 0x02020000) >> 14) | ((D & 0x00400000) >> 21);
                            round_key[2 * i + 1] =
                                ((C & 0x00000001) << 28) | ((C & 0x00000082) << 18) | ((C & 0x00002000) << 14) |
                                ((C & 0x00000100) << 10) | ((C & 0x00001000) << 9) | ((C & 0x00040000) << 6) |
                                ((C & 0x02400000) << 4) | ((C & 0x00008000) << 2) | ((C & 0x00200000) >> 1) |
                                ((C & 0x04000000) >> 10) | ((D & 0x00000020) << 6) | ((D & 0x00000100)) |
                                ((D & 0x00000800) >> 1) | ((D & 0x00000040) >> 3) | ((D & 0x00010000) >> 4) |
                                ((D & 0x00000400) >> 5) | ((D & 0x00004000) >> 10) | ((D & 0x04000000) >> 13) |
                                ((D & 0x00800000) >> 14) | ((D & 0x00100000) >> 18) | ((D & 0x01000000) >> 24) |
                                ((D & 0x08000000) >> 26);
                        }
                    }

                    inline static word_type spbox(word_type T0, word_type T1) {
                        return policy_type::sbox1[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T0, 0)] ^
                               policy_type::sbox2[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T1, 0)] ^
                               policy_type::sbox3[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T0, 1)] ^
                               policy_type::sbox4[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T1, 1)] ^
                               policy_type::sbox5[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T0, 2)] ^
                               policy_type::sbox6[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T1, 2)] ^
                               policy_type::sbox7[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T0, 3)] ^
                               policy_type::sbox8[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(T1, 3)];
                    }

                    inline static void des_encrypt(word_type &L, word_type &R, const key_schedule_type &round_key) {
                        for (size_t i = 0; i != policy_type::rounds; i += 2) {
                            L ^= spbox(policy_type::template rotr<4>(R) ^ round_key[2 * i], R ^ round_key[2 * i + 1]);
                            R ^= spbox(policy_type::template rotr<4>(L) ^ round_key[2 * i + 2],
                                       L ^ round_key[2 * i + 3]);
                        }
                    }

                    inline static void des_decrypt(word_type &L, word_type &R, const key_schedule_type &round_key) {
                        for (size_t i = policy_type::rounds; i != 0; i -= 2) {
                            L ^= spbox(policy_type::template rotr<4>(R) ^ round_key[2 * i - 2],
                                       R ^ round_key[2 * i - 1]);
                            R ^= spbox(policy_type::template rotr<4>(L) ^ round_key[2 * i - 4],
                                       L ^ round_key[2 * i - 3]);
                        }
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DES_FUNCTIONS_HPP
