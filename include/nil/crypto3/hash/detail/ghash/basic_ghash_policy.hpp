//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_GHASH_BASIC_POLICY_HPP
#define CRYPTO3_HASH_GHASH_BASIC_POLICY_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <vector>
namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<template<typename> class Allocator>
                struct basic_ghash_policy {
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t word_bits = 64;
                    typedef typename boost::uint_t<word_bits>::exact word_type;

                    constexpr static const std::size_t block_words = 2;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t rounds = 64;

                    constexpr static const std::size_t key_size = 256;
                    typedef std::array<byte_type, key_size> key_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    constexpr static const std::size_t digest_bits = block_bits;
                    constexpr static const std::size_t digest_words = block_words;
                    typedef static_digest<digest_bits> digest_type;

                    typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>>
                        associated_data_type;
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_GHASH_POLICY_HPP
