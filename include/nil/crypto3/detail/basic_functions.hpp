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
                constexpr static const std::size_t byte_bits = CHAR_BIT;
                typedef typename boost::uint_t<byte_bits>::exact byte_type;

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

            template<>
            struct basic_functions<32> {
                constexpr static const std::size_t byte_bits = CHAR_BIT;
                typedef typename boost::uint_t<byte_bits>::exact byte_type;

                constexpr static const std::size_t word_bits = 32;
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
#if defined(BOOST_ARCH_X86)
                    asm("rorl %1,%0" : "+r"(x) : "c"(static_cast<uint8_t>(n)));
                    return x;
#else
                    return shr(x, n) | shl(x, word_bits - n);
#endif
                }

                template<std::size_t n>
                static inline word_type rotr(word_type x) {
                    return shr<n>(x) | shl<word_bits - n>(x);
                }

                static inline word_type rotl(word_type x, std::size_t n) {
#if defined(BOOST_ARCH_X86)
                    asm("roll %1,%0" : "+r"(x) : "c"(static_cast<uint8_t>(n)));
                    return x;
#else
                    return shl(x, n) | shr(x, word_bits - n);
#endif
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
