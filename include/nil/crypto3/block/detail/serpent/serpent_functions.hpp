//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SERPENT_FUNCTIONS_CPP_HPP
#define CRYPTO3_SERPENT_FUNCTIONS_CPP_HPP

#include <boost/endian/arithmetic.hpp>

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct serpent_functions : public ::nil::crypto3::detail::basic_functions<WordBits> {
                    typedef ::nil::crypto3::detail::basic_functions<WordBits> policy_type;
                    typedef typename policy_type::word_type word_type;

                    /*
                     * Serpent's Linear Transform
                     */
                    inline static void transform(word_type &B0, word_type &B1, word_type &B2, word_type &B3) {
                        B0 = policy_type::rotl<13>(B0);
                        B2 = policy_type::rotl<3>(B2);
                        B1 ^= B0 ^ B2;
                        B3 ^= B2 ^ (B0 << 3);
                        B1 = policy_type::rotl<1>(B1);
                        B3 = policy_type::rotl<7>(B3);
                        B0 ^= B1 ^ B3;
                        B2 ^= B3 ^ (B1 << 7);
                        B0 = policy_type::rotl<5>(B0);
                        B2 = policy_type::rotl<22>(B2);
                    }

                    /*
                     * Serpent's Inverse Linear Transform
                     */
                    inline static void i_transform(word_type &B0, word_type &B1, word_type &B2, word_type &B3) {
                        B2 = policy_type::rotr<22>(B2);
                        B0 = policy_type::rotr<5>(B0);
                        B2 ^= B3 ^ (B1 << 7);
                        B0 ^= B1 ^ B3;
                        B3 = policy_type::rotr<7>(B3);
                        B1 = policy_type::rotr<1>(B1);
                        B3 ^= B2 ^ (B0 << 3);
                        B1 ^= B0 ^ B2;
                        B2 = policy_type::rotr<3>(B2);
                        B0 = policy_type::rotr<13>(B0);
                    }
                };

                /*
                 * Serpent SBox Expressions
                 *
                 * The sbox expressions used here were discovered by Dag Arne Osvik and
                 * are described in his paper "Speeding Up Serpent".
                 */

#define SBoxE1(B0, B1, B2, B3) \
    do {                       \
        B3 ^= B0;              \
        auto B4 = B1;          \
        B1 &= B3;              \
        B4 ^= B2;              \
        B1 ^= B0;              \
        B0 |= B3;              \
        B0 ^= B4;              \
        B4 ^= B3;              \
        B3 ^= B2;              \
        B2 |= B1;              \
        B2 ^= B4;              \
        B4 = ~B4;              \
        B4 |= B1;              \
        B1 ^= B3;              \
        B1 ^= B4;              \
        B3 |= B0;              \
        B1 ^= B3;              \
        B4 ^= B3;              \
        B3 = B0;               \
        B0 = B1;               \
        B1 = B4;               \
    } while (0)

#define SBoxE2(B0, B1, B2, B3) \
    do {                       \
        B0 = ~B0;              \
        B2 = ~B2;              \
        auto B4 = B0;          \
        B0 &= B1;              \
        B2 ^= B0;              \
        B0 |= B3;              \
        B3 ^= B2;              \
        B1 ^= B0;              \
        B0 ^= B4;              \
        B4 |= B1;              \
        B1 ^= B3;              \
        B2 |= B0;              \
        B2 &= B4;              \
        B0 ^= B1;              \
        B1 &= B2;              \
        B1 ^= B0;              \
        B0 &= B2;              \
        B4 ^= B0;              \
        B0 = B2;               \
        B2 = B3;               \
        B3 = B1;               \
        B1 = B4;               \
    } while (0)

#define SBoxE3(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B0;          \
        B0 &= B2;              \
        B0 ^= B3;              \
        B2 ^= B1;              \
        B2 ^= B0;              \
        B3 |= B4;              \
        B3 ^= B1;              \
        B4 ^= B2;              \
        B1 = B3;               \
        B3 |= B4;              \
        B3 ^= B0;              \
        B0 &= B1;              \
        B4 ^= B0;              \
        B1 ^= B3;              \
        B1 ^= B4;              \
        B0 = B2;               \
        B2 = B1;               \
        B1 = B3;               \
        B3 = ~B4;              \
    } while (0)

#define SBoxE4(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B0;          \
        B0 |= B3;              \
        B3 ^= B1;              \
        B1 &= B4;              \
        B4 ^= B2;              \
        B2 ^= B3;              \
        B3 &= B0;              \
        B4 |= B1;              \
        B3 ^= B4;              \
        B0 ^= B1;              \
        B4 &= B0;              \
        B1 ^= B3;              \
        B4 ^= B2;              \
        B1 |= B0;              \
        B1 ^= B2;              \
        B0 ^= B3;              \
        B2 = B1;               \
        B1 |= B3;              \
        B0 ^= B1;              \
        B1 = B2;               \
        B2 = B3;               \
        B3 = B4;               \
    } while (0)

#define SBoxE5(B0, B1, B2, B3) \
    do {                       \
        B1 ^= B3;              \
        B3 = ~B3;              \
        B2 ^= B3;              \
        B3 ^= B0;              \
        auto B4 = B1;          \
        B1 &= B3;              \
        B1 ^= B2;              \
        B4 ^= B3;              \
        B0 ^= B4;              \
        B2 &= B4;              \
        B2 ^= B0;              \
        B0 &= B1;              \
        B3 ^= B0;              \
        B4 |= B1;              \
        B4 ^= B0;              \
        B0 |= B3;              \
        B0 ^= B2;              \
        B2 &= B3;              \
        B0 = ~B0;              \
        B4 ^= B2;              \
        B2 = B0;               \
        B0 = B1;               \
        B1 = B4;               \
    } while (0)

#define SBoxE6(B0, B1, B2, B3) \
    do {                       \
        B0 ^= B1;              \
        B1 ^= B3;              \
        B3 = ~B3;              \
        auto B4 = B1;          \
        B1 &= B0;              \
        B2 ^= B3;              \
        B1 ^= B2;              \
        B2 |= B4;              \
        B4 ^= B3;              \
        B3 &= B1;              \
        B3 ^= B0;              \
        B4 ^= B1;              \
        B4 ^= B2;              \
        B2 ^= B0;              \
        B0 &= B3;              \
        B2 = ~B2;              \
        B0 ^= B4;              \
        B4 |= B3;              \
        B4 ^= B2;              \
        B2 = B0;               \
        B0 = B1;               \
        B1 = B3;               \
        B3 = B4;               \
    } while (0)

#define SBoxE7(B0, B1, B2, B3) \
    do {                       \
        B2 = ~B2;              \
        auto B4 = B3;          \
        B3 &= B0;              \
        B0 ^= B4;              \
        B3 ^= B2;              \
        B2 |= B4;              \
        B1 ^= B3;              \
        B2 ^= B0;              \
        B0 |= B1;              \
        B2 ^= B1;              \
        B4 ^= B0;              \
        B0 |= B3;              \
        B0 ^= B2;              \
        B4 ^= B3;              \
        B4 ^= B0;              \
        B3 = ~B3;              \
        B2 &= B4;              \
        B3 ^= B2;              \
        B2 = B4;               \
    } while (0)

#define SBoxE8(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B1;          \
        B1 |= B2;              \
        B1 ^= B3;              \
        B4 ^= B2;              \
        B2 ^= B1;              \
        B3 |= B4;              \
        B3 &= B0;              \
        B4 ^= B2;              \
        B3 ^= B1;              \
        B1 |= B4;              \
        B1 ^= B0;              \
        B0 |= B4;              \
        B0 ^= B2;              \
        B1 ^= B4;              \
        B2 ^= B1;              \
        B1 &= B0;              \
        B1 ^= B4;              \
        B2 = ~B2;              \
        B2 |= B0;              \
        B4 ^= B2;              \
        B2 = B1;               \
        B1 = B3;               \
        B3 = B0;               \
        B0 = B4;               \
    } while (0)

#define SBoxD1(B0, B1, B2, B3) \
    do {                       \
        B2 = ~B2;              \
        auto B4 = B1;          \
        B1 |= B0;              \
        B4 = ~B4;              \
        B1 ^= B2;              \
        B2 |= B4;              \
        B1 ^= B3;              \
        B0 ^= B4;              \
        B2 ^= B0;              \
        B0 &= B3;              \
        B4 ^= B0;              \
        B0 |= B1;              \
        B0 ^= B2;              \
        B3 ^= B4;              \
        B2 ^= B1;              \
        B3 ^= B0;              \
        B3 ^= B1;              \
        B2 &= B3;              \
        B4 ^= B2;              \
        B2 = B1;               \
        B1 = B4;               \
    } while (0)

#define SBoxD2(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B1;          \
        B1 ^= B3;              \
        B3 &= B1;              \
        B4 ^= B2;              \
        B3 ^= B0;              \
        B0 |= B1;              \
        B2 ^= B3;              \
        B0 ^= B4;              \
        B0 |= B2;              \
        B1 ^= B3;              \
        B0 ^= B1;              \
        B1 |= B3;              \
        B1 ^= B0;              \
        B4 = ~B4;              \
        B4 ^= B1;              \
        B1 |= B0;              \
        B1 ^= B0;              \
        B1 |= B4;              \
        B3 ^= B1;              \
        B1 = B0;               \
        B0 = B4;               \
        B4 = B2;               \
        B2 = B3;               \
        B3 = B4;               \
    } while (0)

#define SBoxD3(B0, B1, B2, B3) \
    do {                       \
        B2 ^= B3;              \
        B3 ^= B0;              \
        auto B4 = B3;          \
        B3 &= B2;              \
        B3 ^= B1;              \
        B1 |= B2;              \
        B1 ^= B4;              \
        B4 &= B3;              \
        B2 ^= B3;              \
        B4 &= B0;              \
        B4 ^= B2;              \
        B2 &= B1;              \
        B2 |= B0;              \
        B3 = ~B3;              \
        B2 ^= B3;              \
        B0 ^= B3;              \
        B0 &= B1;              \
        B3 ^= B4;              \
        B3 ^= B0;              \
        B0 = B1;               \
        B1 = B4;               \
    } while (0)

#define SBoxD4(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B2;          \
        B2 ^= B1;              \
        B0 ^= B2;              \
        B4 &= B2;              \
        B4 ^= B0;              \
        B0 &= B1;              \
        B1 ^= B3;              \
        B3 |= B4;              \
        B2 ^= B3;              \
        B0 ^= B3;              \
        B1 ^= B4;              \
        B3 &= B2;              \
        B3 ^= B1;              \
        B1 ^= B0;              \
        B1 |= B2;              \
        B0 ^= B3;              \
        B1 ^= B4;              \
        B0 ^= B1;              \
        B4 = B0;               \
        B0 = B2;               \
        B2 = B3;               \
        B3 = B4;               \
    } while (0)

#define SBoxD5(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B2;          \
        B2 &= B3;              \
        B2 ^= B1;              \
        B1 |= B3;              \
        B1 &= B0;              \
        B4 ^= B2;              \
        B4 ^= B1;              \
        B1 &= B2;              \
        B0 = ~B0;              \
        B3 ^= B4;              \
        B1 ^= B3;              \
        B3 &= B0;              \
        B3 ^= B2;              \
        B0 ^= B1;              \
        B2 &= B0;              \
        B3 ^= B0;              \
        B2 ^= B4;              \
        B2 |= B3;              \
        B3 ^= B0;              \
        B2 ^= B1;              \
        B1 = B3;               \
        B3 = B4;               \
    } while (0)

#define SBoxD6(B0, B1, B2, B3) \
    do {                       \
        B1 = ~B1;              \
        auto B4 = B3;          \
        B2 ^= B1;              \
        B3 |= B0;              \
        B3 ^= B2;              \
        B2 |= B1;              \
        B2 &= B0;              \
        B4 ^= B3;              \
        B2 ^= B4;              \
        B4 |= B0;              \
        B4 ^= B1;              \
        B1 &= B2;              \
        B1 ^= B3;              \
        B4 ^= B2;              \
        B3 &= B4;              \
        B4 ^= B1;              \
        B3 ^= B4;              \
        B4 = ~B4;              \
        B3 ^= B0;              \
        B0 = B1;               \
        B1 = B4;               \
        B4 = B3;               \
        B3 = B2;               \
        B2 = B4;               \
    } while (0)

#define SBoxD7(B0, B1, B2, B3) \
    do {                       \
        B0 ^= B2;              \
        auto B4 = B2;          \
        B2 &= B0;              \
        B4 ^= B3;              \
        B2 = ~B2;              \
        B3 ^= B1;              \
        B2 ^= B3;              \
        B4 |= B0;              \
        B0 ^= B2;              \
        B3 ^= B4;              \
        B4 ^= B1;              \
        B1 &= B3;              \
        B1 ^= B0;              \
        B0 ^= B3;              \
        B0 |= B2;              \
        B3 ^= B1;              \
        B4 ^= B0;              \
        B0 = B1;               \
        B1 = B2;               \
        B2 = B4;               \
    } while (0)

#define SBoxD8(B0, B1, B2, B3) \
    do {                       \
        auto B4 = B2;          \
        B2 ^= B0;              \
        B0 &= B3;              \
        B4 |= B3;              \
        B2 = ~B2;              \
        B3 ^= B1;              \
        B1 |= B0;              \
        B0 ^= B2;              \
        B2 &= B4;              \
        B3 &= B4;              \
        B1 ^= B2;              \
        B2 ^= B0;              \
        B0 |= B2;              \
        B4 ^= B1;              \
        B0 ^= B3;              \
        B3 ^= B4;              \
        B4 |= B0;              \
        B3 ^= B2;              \
        B4 ^= B2;              \
        B2 = B1;               \
        B1 = B0;               \
        B0 = B3;               \
        B3 = B4;               \
    } while (0)
/*
 * XOR a key block with a data block
 */
#define key_xor(round, B0, B1, B2, B3) \
    B0 ^= key_schedule[4 * round];     \
    B1 ^= key_schedule[4 * round + 1]; \
    B2 ^= key_schedule[4 * round + 2]; \
    B3 ^= key_schedule[4 * round + 3];
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SERPENT_FUNCTIONS_CPP_HPP
