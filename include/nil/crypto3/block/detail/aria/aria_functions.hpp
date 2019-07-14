//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ARIA_FUNCTIONS_CPP_HPP
#define CRYPTO3_ARIA_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/aria/basic_aria_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t KeyBits>
                struct aria_functions : public basic_aria_policy<KeyBits> {
                    typedef basic_aria_policy<KeyBits> policy_type;

                    typedef typename policy_type::word_type word_type;

                    inline static void fo(word_type &T0, word_type &T1, word_type &T2, word_type &T3) {
                        T0 = policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T0, 0)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T0, 1)] ^
                             policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T0, 2)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T0, 3)];
                        T1 = policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T1, 0)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T1, 1)] ^
                             policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T1, 2)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T1, 3)];
                        T2 = policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T2, 0)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T2, 1)] ^
                             policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T2, 2)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T2, 3)];
                        T3 = policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T3, 0)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T3, 1)] ^
                             policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T3, 2)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T3, 3)];

                        T1 ^= T2;
                        T2 ^= T3;
                        T0 ^= T1;
                        T3 ^= T1;
                        T2 ^= T0;
                        T1 ^= T2;

                        T1 = ((T1 << 8) & 0xFF00FF00) | ((T1 >> 8) & 0x00FF00FF);
                        T2 = policy_type::rotr<16>(T2);
                        T3 = reverse_bytes(T3);

                        T1 ^= T2;
                        T2 ^= T3;
                        T0 ^= T1;
                        T3 ^= T1;
                        T2 ^= T0;
                        T1 ^= T2;
                    }

                    inline static void fe(word_type &T0, word_type &T1, word_type &T2, word_type &T3) {
                        T0 = policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T0, 0)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T0, 1)] ^
                             policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T0, 2)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T0, 3)];
                        T1 = policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T1, 0)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T1, 1)] ^
                             policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T1, 2)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T1, 3)];
                        T2 = policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T2, 0)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T2, 1)] ^
                             policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T2, 2)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T2, 3)];
                        T3 = policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(T3, 0)] ^
                             policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(T3, 1)] ^
                             policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(T3, 2)] ^
                             policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(T3, 3)];

                        T1 ^= T2;
                        T2 ^= T3;
                        T0 ^= T1;
                        T3 ^= T1;
                        T2 ^= T0;
                        T1 ^= T2;

                        T3 = ((T3 << 8) & 0xFF00FF00) | ((T3 >> 8) & 0x00FF00FF);
                        T0 = policy_type::rotr<16>(T0);
                        T1 = reverse_bytes(T1);

                        T1 ^= T2;
                        T2 ^= T3;
                        T0 ^= T1;
                        T3 ^= T1;
                        T2 ^= T0;
                        T1 ^= T2;
                    }

                    // n-bit right shift of Y XORed to X
                    template<unsigned int N>
                    inline static void rol128(const word_type X[4], const word_type Y[4], word_type KS[4]) {
                        // MSVC is not generating a "rotate immediate". Constify to help it along.
                        static const unsigned int Q = 4 - (N / 32);
                        static const unsigned int R = N % 32;
                        KS[0] = (X[0]) ^ ((Y[(Q) % 4]) >> R) ^ ((Y[(Q + 3) % 4]) << (32 - R));
                        KS[1] = (X[1]) ^ ((Y[(Q + 1) % 4]) >> R) ^ ((Y[(Q) % 4]) << (32 - R));
                        KS[2] = (X[2]) ^ ((Y[(Q + 2) % 4]) >> R) ^ ((Y[(Q + 1) % 4]) << (32 - R));
                        KS[3] = (X[3]) ^ ((Y[(Q + 3) % 4]) >> R) ^ ((Y[(Q + 2) % 4]) << (32 - R));
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ARIA_FUNCTIONS_CPP_HPP
