//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BASIC_FUNCTIONS_HPP
#define CRYPTO3_BASIC_FUNCTIONS_HPP

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>

#include <nil/crypto3/detail/make_uint_t.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<std::size_t WordBits>
            struct basic_functions {
                typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                constexpr static const std::size_t word_bits = WordBits;
                typedef typename boost::uint_t<word_bits>::exact word_type;

                static inline word_type shr(word_type x, std::size_t n) {
                    return x >> n;
                }

                template<std::size_t n>
                static inline word_type shr(word_type x) {
                    BOOST_STATIC_ASSERT(n < word_bits);
                    return x >> n;
                }

                static inline word_type shl(word_type x, std::size_t n) {
                    return x << n;
                }

                template<std::size_t n>
                static inline word_type shl(word_type x) {
                    BOOST_STATIC_ASSERT(n < word_bits);
                    return x << n;
                }

                static inline word_type rotr(word_type x, std::size_t n) {
                    return shr(x, n) | shl(x, word_bits - n);
                }

                template<std::size_t n>
                static inline word_type rotr(word_type x) {
                    return shr<n>(x) | shl<word_bits - n>(x);
                }

                static inline word_type rotl(word_type x, std::size_t n) {
                    return shl(x, n) | shr(x, word_bits - n);
                }

                template<std::size_t n>
                static inline word_type rotl(word_type x) {
                    return shl<n>(x) | shr<word_bits - n>(x);
                }
            };
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BASIC_FUNCTIONS_HPP
