//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_WHIRLPOOL_HPP
#define CRYPTO3_WHIRLPOOL_HPP

#include <nil/crypto3/hash/detail/state_adder.hpp>
#include <nil/crypto3/hash/detail/miyaguchi_preneel_compressor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/hash_stream_processor.hpp>

#include <nil/crypto3/hash/detail/whirlpool/whirlpool_cipher.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            struct whirlpool_key_converter {
                typedef detail::whirlpool_policy policy_type;
                typedef detail::whirlpool_cipher block_cipher_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                typedef typename block_cipher_type::key_type key_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                void operator()(key_type &key, const state_type &state) {
                    key = state;
                }
            };

            /*!
             * @brief Whirlpool. A 512-bit hash function standardized by ISO and
             * NESSIE. Relatively slow, and due to the table based implementation it
             * is (unlike almost all other hashes) potentially vulnerable to cache
             * based side channels. Prefer Skein-512 or BLAKE2b in new code.
             *
             * @ingroup hash
             */
            class whirlpool {
                typedef detail::whirlpool_policy policy_type;
                typedef detail::whirlpool_cipher block_cipher_type;

            public:
                struct construction {
                    struct params_type {
                        typedef typename stream_endian::big_octet_big_bit digest_endian;

                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef merkle_damgard_construction<
                        params_type, typename policy_type::iv_generator,
                        miyaguchi_preneel_compressor<block_cipher_type, detail::state_adder, whirlpool_key_converter>>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::big_octet_big_bit endian;

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
