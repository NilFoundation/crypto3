//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_WHIRLPOOL_H_
#define CRYPTO3_WHIRLPOOL_H_

#include <nil/crypto3/hash/detail/state_adder.hpp>
#include <nil/crypto3/hash/detail/miyaguchi_preneel_compressor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_state_preprocessor.hpp>

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
                typedef merkle_damgard_construction<stream_endian::big_octet_big_bit, policy_type::digest_bits,
                                                    typename policy_type::iv_generator,
                                                    miyaguchi_preneel_compressor<block_cipher_type, detail::state_adder,
                                                                                 whirlpool_key_converter>> block_hash_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef block_hash_type_ block_hash_type;
#else
                struct block_hash_type : block_hash_type_ {
                };
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    typedef merkle_damgard_state_preprocessor<block_hash_type, StateAccumulator,
                                                              stream_endian::big_octet_big_bit, ValueBits,
                                                              block_hash_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };
                typedef typename block_hash_type::digest_type digest_type;
            };
        }
    }
}

#endif
