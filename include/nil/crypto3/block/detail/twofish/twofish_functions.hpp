//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TWOFISH_FUNCTIONS_CPP_HPP
#define CRYPTO3_TWOFISH_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/twofish/basic_twofish_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t KeyBits>
                struct twofish_functions : public basic_twofish_policy<KeyBits> {
                    typedef basic_twofish_policy<KeyBits> policy_type;
                    typedef typename policy_type::word_type word_type;

                    typedef
                        typename basic_twofish_policy<KeyBits>::expanded_substitution_type expanded_substitution_type;

                    inline static void tf_e(word_type A, word_type B, word_type &C, word_type &D, word_type RK1,
                                            word_type RK2, const expanded_substitution_type &SB) {
                        word_type X = SB[policy_type::template extract_uint_t<CHAR_BIT>(A, 3)] ^
                                      SB[256 + policy_type::template extract_uint_t<CHAR_BIT>(A, 2)] ^
                                      SB[512 + policy_type::template extract_uint_t<CHAR_BIT>(A, 1)] ^
                                      SB[768 + policy_type::template extract_uint_t<CHAR_BIT>(A, 0)];
                        word_type Y = SB[policy_type::template extract_uint_t<CHAR_BIT>(B, 0)] ^
                                      SB[256 + policy_type::template extract_uint_t<CHAR_BIT>(B, 3)] ^
                                      SB[512 + policy_type::template extract_uint_t<CHAR_BIT>(B, 2)] ^
                                      SB[768 + policy_type::template extract_uint_t<CHAR_BIT>(B, 1)];

                        X += Y;
                        Y += X;

                        X += RK1;
                        Y += RK2;

                        C = policy_type::template rotr<1>(C ^ X);
                        D = policy_type::template rotl<1>(D) ^ Y;
                    }

                    inline static void tf_d(word_type A, word_type B, word_type &C, word_type &D, word_type RK1,
                                            word_type RK2, const expanded_substitution_type &SB) {
                        word_type X = SB[policy_type::template extract_uint_t<CHAR_BIT>(A, 3)] ^
                                      SB[256 + policy_type::template extract_uint_t<CHAR_BIT>(A, 2)] ^
                                      SB[512 + policy_type::template extract_uint_t<CHAR_BIT>(A, 1)] ^
                                      SB[768 + policy_type::template extract_uint_t<CHAR_BIT>(A, 0)];
                        word_type Y = SB[policy_type::template extract_uint_t<CHAR_BIT>(B, 0)] ^
                                      SB[256 + policy_type::template extract_uint_t<CHAR_BIT>(B, 3)] ^
                                      SB[512 + policy_type::template extract_uint_t<CHAR_BIT>(B, 2)] ^
                                      SB[768 + policy_type::template extract_uint_t<CHAR_BIT>(B, 1)];

                        X += Y;
                        Y += X;

                        X += RK1;
                        Y += RK2;

                        C = policy_type::template rotl<1>(C) ^ X;
                        D = policy_type::template rotr<1>(D ^ Y);
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MISTY1_FUNCTIONS_CPP_HPP
