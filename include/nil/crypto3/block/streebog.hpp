//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_STREEBOG_CIPHER_HPP
#define CRYPTO3_BLOCK_STREEBOG_CIPHER_HPP

#include <nil/crypto3/block/detail/streebog/streebog_functions.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief
             *
             * @ingroup block
             *
             * @tparam BlockBits
             * @tparam KeyBits
             */
            template<std::size_t BlockBits, std::size_t KeyBits>
            class streebog {
                typedef detail::streebog_functions<BlockBits, KeyBits> policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                static const std::size_t rounds = policy_type::rounds;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;

                streebog(const key_type &key) {
                    schedule_key(key);
                }

                ~streebog() {
                    encryption_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return {};
                }

            protected:
                key_schedule_type encryption_key;

                inline block_type encrypt_block(const block_type &plaintext) const {
                    block_type ciphertext = plaintext, A = plaintext, C;

                    for (size_t i = 0; i != block_words; ++i) {
                        ciphertext[i] ^= encryption_key[i];
                    }

                    for (size_t i = 0; i < rounds; ++i) {
                        policy_type::lps(ciphertext);
                        C = boost::endian::native_to_little(
                            &policy_type::round_constants[i * policy_type::substitutions_amount]);

                        for (size_t j = 0; j != block_words; ++j) {
                            A[j] ^= C[j];
                        }
                        policy_type::lps(A);
                        for (size_t j = 0; j != block_words; ++j) {
                            ciphertext[j] ^= A[j];
                        }
                    }
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                }

                inline void schedule_key(const key_type &key) {
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_STREEBOG_HPP
