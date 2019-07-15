//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SKEIN_512_HPP
#define CRYPTO3_SKEIN_512_HPP

#include <nil/crypto3/block/threefish.hpp>

#include <nil/crypto3/hash/detail/skein/skein_policy.hpp>

#include <nil/crypto3/hash/detail/state_adder.hpp>
#include <nil/crypto3/hash/detail/matyas_meyer_oseas_compressor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_stream_processor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>

#include <string>
#include <memory>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t DigestBits>
            struct skein_key_converter {
                typedef detail::skein_policy<DigestBits> policy_type;
                typedef block::threefish<DigestBits> block_cipher_type;

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
             * @brief Skein. A contender for the NIST SHA-3 competition. Considered
             * to be a cryptographically secure Merkle-Damgård construction over
             * threefish block cipher. Very fast on 64-bit systems. Can
             * output a hash of any length between 1 and 64 bytes. It also accepts a
             * "personalization string" which can create variants of the hash. This
             * is useful for domain separation.
             *
             * @ingroup hash
             */
            template<std::size_t DigestBits>
            class skein {
                typedef typename detail::skein_policy<DigestBits> policy_type;
                typedef typename block::threefish<DigestBits> block_cipher_type;

            public:
                typedef merkle_damgard_construction<
                    stream_endian::little_octet_big_bit, policy_type::digest_bits, typename policy_type::iv_generator,
                    matyas_meyer_oseas_compressor<block_cipher_type, detail::state_adder,
                                                  skein_key_converter<DigestBits>>>
                    construction_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef construction_type_ construction_type;
#else
                struct construction_type : construction_type_ {};
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = construction_type::word_bits;
                    };

                    typedef merkle_damgard_stream_processor<construction_type, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename construction_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif
