//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_GHASH_FUNCTIONS_HPP
#define CRYPTO3_HASH_GHASH_FUNCTIONS_HPP

#include <boost/endian/conversion.hpp>

#include <nil/crypto3/hash/detail/ghash/basic_ghash_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<template<typename> class Allocator>
                struct ghash_functions : public basic_ghash_policy<Allocator> {
                    typedef detail::basic_ghash_policy<Allocator> policy_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    block_type gcm_multiply(const block_type &block) {
                        const uint64_t mask = 0xFFFFFFFFFFFFFFFF;

                        block_type in = block, out{word_type(), word_type()};

                        for (size_t i = 0; i != rounds; ++i) {
                            const word_type x0_mask = (mask + (in[0] >> 63)) ^ mask;
                            const word_type x1_mask = (mask + (in[1] >> 63)) ^ mask;

                            in[0] <<= 1;
                            in[1] <<= 1;

//                            out[0] ^= m_HM[4 * i] & x0_mask;
//                            out[1] ^= m_HM[4 * i + 1] & x0_mask;
//                            out[0] ^= m_HM[4 * i + 2] & x1_mask;
//                            out[1] ^= m_HM[4 * i + 3] & x1_mask;
                        }

                        return {boost::endian::native_to_big(out[0]), boost::endian::native_to_big(out[1])};
                    }
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_GHASH_POLICY_HPP
