//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_GHASH_HPP
#define CRYPTO3_HASH_GHASH_HPP

#include <nil/crypto3/hash/detail/ghash_policy.hpp>

#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_stream_processor.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<template<typename> class Allocator>
            class ghash_compressor {
                typedef detail::ghash_policy<Allocator> policy_type;
            public:

            };

            /*!
             * @brief Internal usage intended hash. Purposed for code sharing among gmac and gcm.
             * @tparam Allocator Allocator used for associated data container.
             */
            template<template<typename> class Allocator = std::allocator>
            class ghash {
                typedef detail::ghash_policy<Allocator> policy_type;

            public:
                struct construction {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit digest_endian;

                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef merkle_damgard_construction<params_type, typename policy_type::iv_generator,
                                                        ghash_compressor<Allocator>>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t length_bits = construction::params_type::length_bits;
                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    typedef merkle_damgard_stream_processor<construction, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_GHASH_HPP
