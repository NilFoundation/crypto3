//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLAKE2B_FUNCTIONS_HPP
#define CRYPTO3_BLAKE2B_FUNCTIONS_HPP

#include <array>

#include <nil/crypto3/hash/detail/blake2b/blake2b_policy.hpp>

#include <boost/static_assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct blake2b_functions : public blake2b_policy<DigestBits> {
                    constexpr static const std::size_t word_bits = blake2b_policy<DigestBits>::word_bits;
                    typedef typename blake2b_policy<DigestBits>::word_type word_type;

                    constexpr static const std::size_t block_bits = blake2b_policy<DigestBits>::block_bits;
                    constexpr static const std::size_t block_words = blake2b_policy<DigestBits>::block_words;
                    typedef typename blake2b_policy<DigestBits>::block_type block_type;

                    constexpr static const std::size_t state_bits = blake2b_policy<DigestBits>::state_bits;
                    constexpr static const std::size_t state_words = blake2b_policy<DigestBits>::state_words;
                    typedef typename blake2b_policy<DigestBits>::state_type state_type;

                    inline static void g(word_type &a, word_type &b, word_type &c, word_type &d, word_type M0,
                                         word_type M1) {
                        using namespace ::nil::crypto3::detail;

                        a = a + b + M0;
                        d = basic_functions<64>::template rotr<32>(d ^ a);
                        c = c + d;
                        b = basic_functions<64>::template rotr<24>(b ^ c);
                        a = a + b + M1;
                        d = basic_functions<64>::template rotr<16>(d ^ a);
                        c = c + d;
                        b = basic_functions<64>::template rotr<63>(b ^ c);
                    }

                    template<size_t i0, size_t i1, size_t i2, size_t i3, size_t i4, size_t i5, size_t i6, size_t i7,
                             size_t i8, size_t i9, size_t iA, size_t iB, size_t iC, size_t iD, size_t iE, size_t iF>
                    inline static void round(std::array<word_type, state_words * 2> &v,
                                             const std::array<word_type, state_words * 2> &M) {
                        g(v[0], v[4], v[8], v[12], M[i0], M[i1]);
                        g(v[1], v[5], v[9], v[13], M[i2], M[i3]);
                        g(v[2], v[6], v[10], v[14], M[i4], M[i5]);
                        g(v[3], v[7], v[11], v[15], M[i6], M[i7]);
                        g(v[0], v[5], v[10], v[15], M[i8], M[i9]);
                        g(v[1], v[6], v[11], v[12], M[iA], M[iB]);
                        g(v[2], v[7], v[8], v[13], M[iC], M[iD]);
                        g(v[3], v[4], v[9], v[14], M[iE], M[iF]);
                    }
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLAKE2B_FUNCTIONS_HPP
