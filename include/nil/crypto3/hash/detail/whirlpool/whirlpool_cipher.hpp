//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
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

                            T0 = policy_type::sbox0[get_byte(0, K0)] ^ policy_type::sbox1[get_byte(1, K7)] ^
                                 policy_type::sbox2[get_byte(2, K6)] ^ policy_type::sbox3[get_byte(3, K5)] ^
                                 policy_type::sbox4[get_byte(4, K4)] ^ policy_type::sbox5[get_byte(5, K3)] ^
                                 policy_type::sbox6[get_byte(6, K2)] ^ policy_type::sbox7[get_byte(7, K1)] ^
                                 policy_type::round_constants[j];
                            T1 = policy_type::sbox0[get_byte(0, K1)] ^ policy_type::sbox1[get_byte(1, K0)] ^
                                 policy_type::sbox2[get_byte(2, K7)] ^ policy_type::sbox3[get_byte(3, K6)] ^
                                 policy_type::sbox4[get_byte(4, K5)] ^ policy_type::sbox5[get_byte(5, K4)] ^
                                 policy_type::sbox6[get_byte(6, K3)] ^ policy_type::sbox7[get_byte(7, K2)];
                            T2 = policy_type::sbox0[get_byte(0, K2)] ^ policy_type::sbox1[get_byte(1, K1)] ^
                                 policy_type::sbox2[get_byte(2, K0)] ^ policy_type::sbox3[get_byte(3, K7)] ^
                                 policy_type::sbox4[get_byte(4, K6)] ^ policy_type::sbox5[get_byte(5, K5)] ^
                                 policy_type::sbox6[get_byte(6, K4)] ^ policy_type::sbox7[get_byte(7, K3)];
                            T3 = policy_type::sbox0[get_byte(0, K3)] ^ policy_type::sbox1[get_byte(1, K2)] ^
                                 policy_type::sbox2[get_byte(2, K1)] ^ policy_type::sbox3[get_byte(3, K0)] ^
                                 policy_type::sbox4[get_byte(4, K7)] ^ policy_type::sbox5[get_byte(5, K6)] ^
                                 policy_type::sbox6[get_byte(6, K5)] ^ policy_type::sbox7[get_byte(7, K4)];
                            T4 = policy_type::sbox0[get_byte(0, K4)] ^ policy_type::sbox1[get_byte(1, K3)] ^
                                 policy_type::sbox2[get_byte(2, K2)] ^ policy_type::sbox3[get_byte(3, K1)] ^
                                 policy_type::sbox4[get_byte(4, K0)] ^ policy_type::sbox5[get_byte(5, K7)] ^
                                 policy_type::sbox6[get_byte(6, K6)] ^ policy_type::sbox7[get_byte(7, K5)];
                            T5 = policy_type::sbox0[get_byte(0, K5)] ^ policy_type::sbox1[get_byte(1, K4)] ^
                                 policy_type::sbox2[get_byte(2, K3)] ^ policy_type::sbox3[get_byte(3, K2)] ^
                                 policy_type::sbox4[get_byte(4, K1)] ^ policy_type::sbox5[get_byte(5, K0)] ^
                                 policy_type::sbox6[get_byte(6, K7)] ^ policy_type::sbox7[get_byte(7, K6)];
                            T6 = policy_type::sbox0[get_byte(0, K6)] ^ policy_type::sbox1[get_byte(1, K5)] ^
                                 policy_type::sbox2[get_byte(2, K4)] ^ policy_type::sbox3[get_byte(3, K3)] ^
                                 policy_type::sbox4[get_byte(4, K2)] ^ policy_type::sbox5[get_byte(5, K1)] ^
                                 policy_type::sbox6[get_byte(6, K0)] ^ policy_type::sbox7[get_byte(7, K7)];
                            T7 = policy_type::sbox0[get_byte(0, K7)] ^ policy_type::sbox1[get_byte(1, K6)] ^
                                 policy_type::sbox2[get_byte(2, K5)] ^ policy_type::sbox3[get_byte(3, K4)] ^
                                 policy_type::sbox4[get_byte(4, K3)] ^ policy_type::sbox5[get_byte(5, K2)] ^
                                 policy_type::sbox6[get_byte(6, K1)] ^ policy_type::sbox7[get_byte(7, K0)];

                            K0 = T0;
                            K1 = T1;
                            K2 = T2;
                            K3 = T3;
                            K4 = T4;
                            K5 = T5;
                            K6 = T6;
                            K7 = T7;

                            T0 = policy_type::sbox0[get_byte(0, B0)] ^ policy_type::sbox1[get_byte(1, B7)] ^
                                 policy_type::sbox2[get_byte(2, B6)] ^ policy_type::sbox3[get_byte(3, B5)] ^
                                 policy_type::sbox4[get_byte(4, B4)] ^ policy_type::sbox5[get_byte(5, B3)] ^
                                 policy_type::sbox6[get_byte(6, B2)] ^ policy_type::sbox7[get_byte(7, B1)] ^ K0;
                            T1 = policy_type::sbox0[get_byte(0, B1)] ^ policy_type::sbox1[get_byte(1, B0)] ^
                                 policy_type::sbox2[get_byte(2, B7)] ^ policy_type::sbox3[get_byte(3, B6)] ^
                                 policy_type::sbox4[get_byte(4, B5)] ^ policy_type::sbox5[get_byte(5, B4)] ^
                                 policy_type::sbox6[get_byte(6, B3)] ^ policy_type::sbox7[get_byte(7, B2)] ^ K1;
                            T2 = policy_type::sbox0[get_byte(0, B2)] ^ policy_type::sbox1[get_byte(1, B1)] ^
                                 policy_type::sbox2[get_byte(2, B0)] ^ policy_type::sbox3[get_byte(3, B7)] ^
                                 policy_type::sbox4[get_byte(4, B6)] ^ policy_type::sbox5[get_byte(5, B5)] ^
                                 policy_type::sbox6[get_byte(6, B4)] ^ policy_type::sbox7[get_byte(7, B3)] ^ K2;
                            T3 = policy_type::sbox0[get_byte(0, B3)] ^ policy_type::sbox1[get_byte(1, B2)] ^
                                 policy_type::sbox2[get_byte(2, B1)] ^ policy_type::sbox3[get_byte(3, B0)] ^
                                 policy_type::sbox4[get_byte(4, B7)] ^ policy_type::sbox5[get_byte(5, B6)] ^
                                 policy_type::sbox6[get_byte(6, B5)] ^ policy_type::sbox7[get_byte(7, B4)] ^ K3;
                            T4 = policy_type::sbox0[get_byte(0, B4)] ^ policy_type::sbox1[get_byte(1, B3)] ^
                                 policy_type::sbox2[get_byte(2, B2)] ^ policy_type::sbox3[get_byte(3, B1)] ^
                                 policy_type::sbox4[get_byte(4, B0)] ^ policy_type::sbox5[get_byte(5, B7)] ^
                                 policy_type::sbox6[get_byte(6, B6)] ^ policy_type::sbox7[get_byte(7, B5)] ^ K4;
                            T5 = policy_type::sbox0[get_byte(0, B5)] ^ policy_type::sbox1[get_byte(1, B4)] ^
                                 policy_type::sbox2[get_byte(2, B3)] ^ policy_type::sbox3[get_byte(3, B2)] ^
                                 policy_type::sbox4[get_byte(4, B1)] ^ policy_type::sbox5[get_byte(5, B0)] ^
                                 policy_type::sbox6[get_byte(6, B7)] ^ policy_type::sbox7[get_byte(7, B6)] ^ K5;
                            T6 = policy_type::sbox0[get_byte(0, B6)] ^ policy_type::sbox1[get_byte(1, B5)] ^
                                 policy_type::sbox2[get_byte(2, B4)] ^ policy_type::sbox3[get_byte(3, B3)] ^
                                 policy_type::sbox4[get_byte(4, B2)] ^ policy_type::sbox5[get_byte(5, B1)] ^
                                 policy_type::sbox6[get_byte(6, B0)] ^ policy_type::sbox7[get_byte(7, B7)] ^ K6;
                            T7 = policy_type::sbox0[get_byte(0, B7)] ^ policy_type::sbox1[get_byte(1, B6)] ^
                                 policy_type::sbox2[get_byte(2, B5)] ^ policy_type::sbox3[get_byte(3, B4)] ^
                                 policy_type::sbox4[get_byte(4, B3)] ^ policy_type::sbox5[get_byte(5, B2)] ^
                                 policy_type::sbox6[get_byte(6, B1)] ^ policy_type::sbox7[get_byte(7, B0)] ^ K7;

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
