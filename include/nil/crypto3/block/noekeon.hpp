//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_NOEKEON_HPP
#define CRYPTO3_BLOCK_NOEKEON_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/noekeon/noekeon_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Noekeon. A fast 128-bit cipher by the designers of AES.
             * Easily secured against side channels.
             *
             * @ingroup block
             */
            class noekeon {
            protected:
                typedef detail::noekeon_policy policy_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;

                noekeon(const key_type &key) {
                    schedule_key(key);
                }

                ~noekeon() {
                    encryption_key.fill(0);
                    decryption_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type encryption_key, decryption_key;

                inline block_type encrypt_block(const block_type &plaintext) const {
                    word_type A0 = boost::endian::native_to_big(plaintext[0]);
                    word_type A1 = boost::endian::native_to_big(plaintext[1]);
                    word_type A2 = boost::endian::native_to_big(plaintext[2]);
                    word_type A3 = boost::endian::native_to_big(plaintext[3]);

                    for (size_t j = 0; j != 16; ++j) {
                        A0 ^= policy_type::round_constants[j];
                        policy_type::theta(A0, A1, A2, A3, encryption_key.data());

                        A1 = policy_type::template rotl<1>(A1);
                        A2 = policy_type::template rotl<5>(A2);
                        A3 = policy_type::template rotl<2>(A3);

                        policy_type::gamma(A0, A1, A2, A3);

                        A1 = policy_type::template rotr<1>(A1);
                        A2 = policy_type::template rotr<5>(A2);
                        A3 = policy_type::template rotr<2>(A3);
                    }

                    A0 ^= policy_type::round_constants[16];
                    policy_type::theta(A0, A1, A2, A3, encryption_key.data());

                    return {boost::endian::big_to_native(A0), boost::endian::big_to_native(A1),
                            boost::endian::big_to_native(A2), boost::endian::big_to_native(A3)};
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    word_type A0 = boost::endian::native_to_big(ciphertext[0]);
                    word_type A1 = boost::endian::native_to_big(ciphertext[1]);
                    word_type A2 = boost::endian::native_to_big(ciphertext[2]);
                    word_type A3 = boost::endian::native_to_big(ciphertext[3]);

                    for (size_t j = 16; j != 0; --j) {
                        policy_type::theta(A0, A1, A2, A3, decryption_key.data());
                        A0 ^= policy_type::round_constants[j];

                        A1 = policy_type::template rotl<1>(A1);
                        A2 = policy_type::template rotl<5>(A2);
                        A3 = policy_type::template rotl<2>(A3);

                        policy_type::gamma(A0, A1, A2, A3);

                        A1 = policy_type::template rotr<1>(A1);
                        A2 = policy_type::template rotr<5>(A2);
                        A3 = policy_type::template rotr<2>(A3);
                    }

                    policy_type::theta(A0, A1, A2, A3, decryption_key.data());
                    A0 ^= policy_type::round_constants[0];

                    return {boost::endian::big_to_native(A0), boost::endian::big_to_native(A1),
                            boost::endian::big_to_native(A2), boost::endian::big_to_native(A3)};
                }

                inline void schedule_key(const key_type &key) {
                    word_type A0 = boost::endian::native_to_big(key[0]);
                    word_type A1 = boost::endian::native_to_big(key[1]);
                    word_type A2 = boost::endian::native_to_big(key[2]);
                    word_type A3 = boost::endian::native_to_big(key[3]);

                    for (size_t i = 0; i != 16; ++i) {
                        A0 ^= policy_type::round_constants[i];
                        policy_type::theta(A0, A1, A2, A3);

                        A1 = policy_type::template rotl<1>(A1);
                        A2 = policy_type::template rotl<5>(A2);
                        A3 = policy_type::template rotl<2>(A3);

                        policy_type::gamma(A0, A1, A2, A3);

                        A1 = policy_type::template rotr<1>(A1);
                        A2 = policy_type::template rotr<5>(A2);
                        A3 = policy_type::template rotr<2>(A3);
                    }

                    A0 ^= policy_type::round_constants[16];

                    decryption_key[0] = A0;
                    decryption_key[1] = A1;
                    decryption_key[2] = A2;
                    decryption_key[3] = A3;

                    policy_type::theta(A0, A1, A2, A3);

                    encryption_key[0] = A0;
                    encryption_key[1] = A1;
                    encryption_key[2] = A2;
                    encryption_key[3] = A3;
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil
#endif
