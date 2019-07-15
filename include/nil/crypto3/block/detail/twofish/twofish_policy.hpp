//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TWOFISH_POLICY_HPP
#define CRYPTO3_TWOFISH_POLICY_HPP

#include <nil/crypto3/block/detail/twofish/twofish_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t KeyBits>
                struct twofish_policy : public twofish_functions<KeyBits> {};

                template<>
                struct twofish_policy<128> : public twofish_functions<128> {
                    inline void static schedule_key(const key_type &key,
                                                    expanded_substitution_type &expanded_substitution,
                                                    key_schedule_type &round_key) {
                        std::array<byte_type, 16> S = {0};

                        for (size_t i = 0; i != key.size(); ++i) {
                            /*
                             * Do one column of the RS matrix multiplication
                             */
                            if (key[i]) {
                                byte_type X = poly_to_exp[key[i] - 1];

                                byte_type RS1 = round_substitution[(4 * i) % 32];
                                byte_type RS2 = round_substitution[(4 * i + 1) % 32];
                                byte_type RS3 = round_substitution[(4 * i + 2) % 32];
                                byte_type RS4 = round_substitution[(4 * i + 3) % 32];

                                S[4 * (i / 8)] ^= exp_to_poly[(X + poly_to_exp[RS1 - 1]) % 255];
                                S[4 * (i / 8) + 1] ^= exp_to_poly[(X + poly_to_exp[RS2 - 1]) % 255];
                                S[4 * (i / 8) + 2] ^= exp_to_poly[(X + poly_to_exp[RS3 - 1]) % 255];
                                S[4 * (i / 8) + 3] ^= exp_to_poly[(X + poly_to_exp[RS4 - 1]) % 255];
                            }
                        }

                        for (size_t i = 0; i != key_schedule_size / 4; ++i) {
                            expanded_substitution[i] = mds0[q0[q0[i] ^ S[0]] ^ S[4]];
                            expanded_substitution[256 + i] = mds1[q0[q1[i] ^ S[1]] ^ S[5]];
                            expanded_substitution[512 + i] = mds2[q1[q0[i] ^ S[2]] ^ S[6]];
                            expanded_substitution[768 + i] = mds3[q1[q1[i] ^ S[3]] ^ S[7]];
                        }

                        for (size_t i = 0; i < expanded_substitution_size; i += 2) {
                            word_type X = mds0[q0[q0[i] ^ key[8]] ^ key[0]] ^ mds1[q0[q1[i] ^ key[9]] ^ key[1]] ^
                                          mds2[q1[q0[i] ^ key[10]] ^ key[2]] ^ mds3[q1[q1[i] ^ key[11]] ^ key[3]];
                            word_type Y =
                                mds0[q0[q0[i + 1] ^ key[12]] ^ key[4]] ^ mds1[q0[q1[i + 1] ^ key[13]] ^ key[5]] ^
                                mds2[q1[q0[i + 1] ^ key[14]] ^ key[6]] ^ mds3[q1[q1[i + 1] ^ key[15]] ^ key[7]];
                            Y = policy_type::template rotl<8>(Y);
                            X += Y;
                            Y += X;

                            round_key[i] = X;
                            round_key[i + 1] = policy_type::template rotl<9>(Y);
                        }

                        S.fill(0);
                    }
                };

                template<>
                struct twofish_policy<192> : public twofish_functions<192> {
                    inline void static schedule_key(const key_type &key,
                                                    expanded_substitution_type &expanded_substitution,
                                                    key_schedule_type &round_key) {
                        std::array<byte_type, 16> S = {0};

                        for (size_t i = 0; i != key.size(); ++i) {
                            /*
                             * Do one column of the RS matrix multiplication
                             */
                            if (key[i]) {
                                byte_type X = poly_to_exp[key[i] - 1];

                                byte_type RS1 = round_substitution[(4 * i) % 32];
                                byte_type RS2 = round_substitution[(4 * i + 1) % 32];
                                byte_type RS3 = round_substitution[(4 * i + 2) % 32];
                                byte_type RS4 = round_substitution[(4 * i + 3) % 32];

                                S[4 * (i / 8)] ^= exp_to_poly[(X + poly_to_exp[RS1 - 1]) % 255];
                                S[4 * (i / 8) + 1] ^= exp_to_poly[(X + poly_to_exp[RS2 - 1]) % 255];
                                S[4 * (i / 8) + 2] ^= exp_to_poly[(X + poly_to_exp[RS3 - 1]) % 255];
                                S[4 * (i / 8) + 3] ^= exp_to_poly[(X + poly_to_exp[RS4 - 1]) % 255];
                            }
                        }

                        for (size_t i = 0; i != key_schedule_size / 4; ++i) {
                            expanded_substitution[i] = mds0[q0[q0[q1[i] ^ S[0]] ^ S[4]] ^ S[8]];
                            expanded_substitution[256 + i] = mds1[q0[q1[q1[i] ^ S[1]] ^ S[5]] ^ S[9]];
                            expanded_substitution[512 + i] = mds2[q1[q0[q0[i] ^ S[2]] ^ S[6]] ^ S[10]];
                            expanded_substitution[768 + i] = mds3[q1[q1[q0[i] ^ S[3]] ^ S[7]] ^ S[11]];
                        }

                        for (size_t i = 0; i < expanded_substitution_size; i += 2) {
                            word_type X = mds0[q0[q0[q1[i] ^ key[16]] ^ key[8]] ^ key[0]] ^
                                          mds1[q0[q1[q1[i] ^ key[17]] ^ key[9]] ^ key[1]] ^
                                          mds2[q1[q0[q0[i] ^ key[18]] ^ key[10]] ^ key[2]] ^
                                          mds3[q1[q1[q0[i] ^ key[19]] ^ key[11]] ^ key[3]];
                            word_type Y = mds0[q0[q0[q1[i + 1] ^ key[20]] ^ key[12]] ^ key[4]] ^
                                          mds1[q0[q1[q1[i + 1] ^ key[21]] ^ key[13]] ^ key[5]] ^
                                          mds2[q1[q0[q0[i + 1] ^ key[22]] ^ key[14]] ^ key[6]] ^
                                          mds3[q1[q1[q0[i + 1] ^ key[23]] ^ key[15]] ^ key[7]];
                            Y = policy_type::template rotl<8>(Y);
                            X += Y;
                            Y += X;

                            round_key[i] = X;
                            round_key[i + 1] = policy_type::template rotl<9>(Y);
                        }

                        S.fill(0);
                    }
                };

                template<>
                struct twofish_policy<256> : public twofish_functions<256> {
                    inline static void schedule_key(const key_type &key,
                                                    expanded_substitution_type &expanded_substitution,
                                                    key_schedule_type &round_key) {
                        std::array<byte_type, 16> S = {0};

                        for (size_t i = 0; i != key.size(); ++i) {
                            /*
                             * Do one column of the RS matrix multiplication
                             */
                            if (key[i]) {
                                byte_type X = poly_to_exp[key[i] - 1];

                                byte_type RS1 = round_substitution[(4 * i) % 32];
                                byte_type RS2 = round_substitution[(4 * i + 1) % 32];
                                byte_type RS3 = round_substitution[(4 * i + 2) % 32];
                                byte_type RS4 = round_substitution[(4 * i + 3) % 32];

                                S[4 * (i / 8)] ^= exp_to_poly[(X + poly_to_exp[RS1 - 1]) % 255];
                                S[4 * (i / 8) + 1] ^= exp_to_poly[(X + poly_to_exp[RS2 - 1]) % 255];
                                S[4 * (i / 8) + 2] ^= exp_to_poly[(X + poly_to_exp[RS3 - 1]) % 255];
                                S[4 * (i / 8) + 3] ^= exp_to_poly[(X + poly_to_exp[RS4 - 1]) % 255];
                            }
                        }

                        for (size_t i = 0; i != key_schedule_size / 4; ++i) {
                            expanded_substitution[i] = mds0[q0[q0[q1[q1[i] ^ S[0]] ^ S[4]] ^ S[8]] ^ S[12]];
                            expanded_substitution[256 + i] = mds1[q0[q1[q1[q0[i] ^ S[1]] ^ S[5]] ^ S[9]] ^ S[13]];
                            expanded_substitution[512 + i] = mds2[q1[q0[q0[q0[i] ^ S[2]] ^ S[6]] ^ S[10]] ^ S[14]];
                            expanded_substitution[768 + i] = mds3[q1[q1[q0[q1[i] ^ S[3]] ^ S[7]] ^ S[11]] ^ S[15]];
                        }

                        for (size_t i = 0; i < expanded_substitution_size; i += 2) {
                            word_type X = mds0[q0[q0[q1[q1[i] ^ key[24]] ^ key[16]] ^ key[8]] ^ key[0]] ^
                                          mds1[q0[q1[q1[q0[i] ^ key[25]] ^ key[17]] ^ key[9]] ^ key[1]] ^
                                          mds2[q1[q0[q0[q0[i] ^ key[26]] ^ key[18]] ^ key[10]] ^ key[2]] ^
                                          mds3[q1[q1[q0[q1[i] ^ key[27]] ^ key[19]] ^ key[11]] ^ key[3]];
                            word_type Y = mds0[q0[q0[q1[q1[i + 1] ^ key[28]] ^ key[20]] ^ key[12]] ^ key[4]] ^
                                          mds1[q0[q1[q1[q0[i + 1] ^ key[29]] ^ key[21]] ^ key[13]] ^ key[5]] ^
                                          mds2[q1[q0[q0[q0[i + 1] ^ key[30]] ^ key[22]] ^ key[14]] ^ key[6]] ^
                                          mds3[q1[q1[q0[q1[i + 1] ^ key[31]] ^ key[23]] ^ key[15]] ^ key[7]];
                            Y = policy_type::template rotl<8>(Y);
                            X += Y;
                            Y += X;

                            round_key[i] = X;
                            round_key[i + 1] = policy_type::template rotl<9>(Y);
                        }

                        S.fill(0);
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TWOFISH_POLICY_HPP
