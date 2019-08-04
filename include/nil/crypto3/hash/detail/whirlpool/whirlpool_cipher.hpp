//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_WHIRLPOOL_CIPHER_HPP
#define CRYPTO3_WHIRLPOOL_CIPHER_HPP

#include <nil/crypto3/hash/detail/whirlpool/whirlpool_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                class whirlpool_cipher {
                    typedef detail::whirlpool_policy policy_type;

                    typedef typename policy_type::key_schedule_type key_schedule_type;
                public:

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    constexpr static const std::size_t key_words = policy_type::key_words;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    whirlpool_cipher(const key_type &key) : key_schedule(key) {

                    }

                    ~whirlpool_cipher() {
                        key_schedule.fill(0);
                    }

                    block_type encrypt(const block_type &plaintext) {
                        return encrypt_block(plaintext);
                    }


                protected:

                    key_schedule_type key_schedule;

                    inline block_type encrypt_block(const block_type &plaintext) {
                        word_type K0 = key_schedule[0];
                        word_type K1 = key_schedule[1];
                        word_type K2 = key_schedule[2];
                        word_type K3 = key_schedule[3];
                        word_type K4 = key_schedule[4];
                        word_type K5 = key_schedule[5];
                        word_type K6 = key_schedule[6];
                        word_type K7 = key_schedule[7];

                        word_type B0 = K0 ^plaintext[0];
                        word_type B1 = K1 ^plaintext[1];
                        word_type B2 = K2 ^plaintext[2];
                        word_type B3 = K3 ^plaintext[3];
                        word_type B4 = K4 ^plaintext[4];
                        word_type B5 = K5 ^plaintext[5];
                        word_type B6 = K6 ^plaintext[6];
                        word_type B7 = K7 ^plaintext[7];

                        for (size_t j = 0; j != rounds; ++j) {
                            word_type T0, T1, T2, T3, T4, T5, T6, T7;

                            T0 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K0, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K7, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K6, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K5, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K4, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K3, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K2, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K1, 7)] ^
                                 policy_type::round_constants[j];
                            T1 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K1, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K0, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K7, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K6, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K5, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K4, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K3, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K2, 7)];
                            T2 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K2, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K1, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K0, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K7, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K6, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K5, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K4, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K3, 7)];
                            T3 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K3, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K2, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K1, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K0, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K7, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K6, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K5, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K4, 7)];
                            T4 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K4, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K3, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K2, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K1, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K0, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K7, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K6, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K5, 7)];
                            T5 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K5, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K4, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K3, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K2, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K1, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K0, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K7, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K6, 7)];
                            T6 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K6, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K5, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K4, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K3, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K2, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K1, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K0, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K7, 7)];
                            T7 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(K7, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(K6, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(K5, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(K4, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(K3, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(K2, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(K1, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(K0, 7)];

                            K0 = T0;
                            K1 = T1;
                            K2 = T2;
                            K3 = T3;
                            K4 = T4;
                            K5 = T5;
                            K6 = T6;
                            K7 = T7;

                            T0 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B0, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B7, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B6, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B5, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B4, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B3, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B2, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B1, 7)] ^ K0;
                            T1 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B1, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B0, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B7, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B6, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B5, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B4, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B3, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B2, 7)] ^ K1;
                            T2 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B2, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B1, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B0, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B7, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B6, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B5, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B4, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B3, 7)] ^ K2;
                            T3 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B3, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B2, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B1, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B0, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B7, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B6, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B5, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B4, 7)] ^ K3;
                            T4 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B4, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B3, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B2, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B1, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B0, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B7, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B6, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B5, 7)] ^ K4;
                            T5 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B5, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B4, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B3, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B2, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B1, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B0, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B7, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B6, 7)] ^ K5;
                            T6 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B6, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B5, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B4, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B3, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B2, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B1, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B0, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B7, 7)] ^ K6;
                            T7 = policy_type::sbox0[policy_type::template extract_uint_t<CHAR_BIT>(B7, 0)] ^
                                 policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B6, 1)] ^
                                 policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B5, 2)] ^
                                 policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B4, 3)] ^
                                 policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B3, 4)] ^
                                 policy_type::sbox5[policy_type::template extract_uint_t<CHAR_BIT>(B2, 5)] ^
                                 policy_type::sbox6[policy_type::template extract_uint_t<CHAR_BIT>(B1, 6)] ^
                                 policy_type::sbox7[policy_type::template extract_uint_t<CHAR_BIT>(B0, 7)] ^ K7;

                            B0 = T0;
                            B1 = T1;
                            B2 = T2;
                            B3 = T3;
                            B4 = T4;
                            B5 = T5;
                            B6 = T6;
                            B7 = T7;
                        }

                        return {B0, B1, B2, B3, B4, B5, B6, B7};
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_WHIRLPOOL_CIPHER_HPP
