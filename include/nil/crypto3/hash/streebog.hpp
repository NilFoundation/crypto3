//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_HASH_HPP
#define CRYPTO3_STREEBOG_HASH_HPP

#include <nil/crypto3/hash/detail/state_adder.hpp>
#include <nil/crypto3/hash/detail/miyaguchi_preneel_compressor.hpp>
#include <nil/crypto3/hash/detail/block_stream_processor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>

#include <nil/crypto3/hash/detail/streebog/streebog_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t DigestBits>
            class streebog_key_converter {};

            /*!
             * @brief Streebog (GOST R 34.11-2012). RFC 6986. Newly designed Russian
             * national hash function. Due to use of input-dependent table lookups,
             * it is vulnerable to side channels. There is no reason to use it unless
             * compatibility is needed.
             *
             * @ingroup hash
             */
            template<std::size_t DigestBits>
            class streebog {
                typedef detail::streebog_policy<DigestBits> policy_type;
                typedef block::streebog<DigestBits, DigestBits> block_cipher_type;

            public:
                struct construction {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit digest_endian;

                        constexpr static const std::size_t length_bits = 0;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef merkle_damgard_construction<
                        params_type, typename policy_type::iv_generator,
                        miyaguchi_preneel_compressor<block_cipher_type, detail::state_adder,
                                                     streebog_key_converter<DigestBits>>>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t length_bits = construction::params_type::length_bits;
                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    typedef hash_stream_processor<construction, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif
