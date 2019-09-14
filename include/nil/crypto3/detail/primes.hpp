//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_DETAIL_PRIMES_HPP
#define CRYPTO3_HASH_DETAIL_PRIMES_HPP

#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<int Bits>
            struct all_ones {
                typedef typename boost::uint_t<Bits>::least type;
                static type const value = (all_ones<Bits - 1>::value << 1) | 1;
            };
            template<>
            struct all_ones<0> {
                typedef boost::uint_t<0>::least type;
                static type const value = 0;
            };

            template<int Bits>
            struct largest_prime;

#define CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(B, D)                              \
    template<>                                                                         \
    struct largest_prime<B> {                                                          \
        constexpr static boost::uint_t<B>::least const value = all_ones<B>::value - D; \
    };                                                                                 \
    constexpr boost::uint_t<B>::least const largest_prime<B>::value;

            // http://primes.utm.edu/lists/2small/0bit.html or
            // http://www.research.att.com/~njas/sequences/A013603
            // Though those offets are from 2**b; This code is offsets from 2**b-1
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(2, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(3, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(4, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(5, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(6, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(7, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(8, 4);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(9, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(10, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(11, 8);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(12, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(13, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(14, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(15, 18);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(16, 14);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(17, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(18, 4);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(19, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(20, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(21, 8);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(22, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(23, 14);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(24, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(25, 38);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(26, 4);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(27, 38);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(28, 56);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(29, 2);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(30, 34);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(31, 0);
            CRYPTO3_HASH_DEFINE_LARGEST_PRIME_BY_OFFSET(32, 4);

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_PRIMES_HPP
