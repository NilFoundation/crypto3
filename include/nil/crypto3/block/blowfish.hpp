//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOWFISH_H_
#define CRYPTO3_BLOWFISH_H_

#include <nil/crypto3/block/detail/blowfish/blowfish_policy.hpp>

#include <nil/crypto3/block/block_cipher.hpp>

#include <nil/crypto3/block/cipher_state.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

#include <nil/crypto3/utilities/loadstore.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Blowfish. A 64-bit cipher popular in the pre-AES era.
             * Very slow key setup. Also used (with bcrypt) for password hashing.
             *
             * @ingroup block
             */
            class blowfish {
            protected:

                typedef detail::blowfish_policy policy_type;

                typedef typename policy_type::permutations_type permutations_type;
                typedef typename policy_type::plain_constants_type plain_constants_type;
                typedef typename policy_type::constants_type constants_type;

            public:

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                typedef typename policy_type::key_type key_type;
                typedef typename policy_type::salt_type salt_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t rounds = policy_type::rounds;

                template<template<typename, typename> class Mode, std::size_t ValueBits, typename Padding>
                struct stream_cipher {
                    typedef cipher_state<Mode<blowfish, Padding>, stream_endian::little_octet_big_bit, ValueBits,
                                         policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                blowfish(const key_type &key, const salt_type &salt = salt_type()) : permutations(
                        policy_type::permutations), constants(policy_type::constants) {
                    key_expansion(key, salt);
                }

                virtual ~blowfish() {
                    permutations.fill(0);
                    constants.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

                void salted_set_key(const key_type &key, const salt_type &salt, std::size_t workfactor) {
                    std::size_t length = key.size();
                    if (key.size() > 72 / sizeof(key_type::value_type)) {
                        // Truncate longer passwords to the 72 char bcrypt limit
                        length = 72;
                    }

                    key_expansion(key_type(key.begin(), key.begin() + length), salt);

                    if (workfactor > 0) {
                        const size_t rnd = static_cast<size_t>(1) << workfactor;

                        for (size_t r = 0; r != rnd; ++r) {
                            key_expansion(key, salt_type());
                            key_expansion(salt, salt_type());
                        }
                    }
                }

            protected:
                permutations_type permutations;
                plain_constants_type constants;

                void key_expansion(const key_type &key, const salt_type &salt) {
                    for (size_t i = 0, j = 0; i != policy_type::permutations_size; ++i, j += word_bits / 8) {
                        permutations[i] ^= key[(j) % key.size()];
                    }

                    const size_t p_salt_offset = (!salt.empty()) ? policy_type::permutations_size % salt.size() : 0;

                    uint32_t L = 0, R = 0;
                    generate_sbox(permutations, L, R, salt, 0);
                    generate_sbox(constants, L, R, salt, p_salt_offset);
                }

                template<typename SubstitutionType>
                void generate_sbox(SubstitutionType &box, word_type &L, word_type &R, const salt_type &salt,
                                   std::size_t salt_off) const {
                    for (size_t i = 0; i != box.size(); i += 2) {
                        if (!salt.empty()) {
                            L ^= salt[(i + salt_off) % (salt.size())];
                            R ^= salt[(i + salt_off + 1) % (salt.size())];
                        }

                        for (size_t r = 0; r != policy_type::rounds; r += 2) {
                            L ^= permutations[r];
                            R ^= policy_type::bff(L, constants);

                            R ^= permutations[r + 1];
                            L ^= policy_type::bff(R, constants);
                        }

                        uint32_t T = R;
                        R = L ^ permutations[16];
                        L = T ^ permutations[17];
                        box[i] = L;
                        box[i + 1] = R;
                    }
                }

                inline block_type encrypt_block(const block_type &plaintext) {
                    word_type L0 = plaintext[0], R0 = plaintext[1];

                    for (size_t r = 0; r != policy_type::rounds; r += 2) {
                        L0 ^= permutations[r];
                        R0 ^= policy_type::bff(L0, constants);

                        R0 ^= permutations[r + 1];
                        L0 ^= policy_type::bff(R0, constants);
                    }

                    L0 ^= permutations[16];
                    R0 ^= permutations[17];

                    return {R0, L0};
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    word_type L0 = ciphertext[0], R0 = ciphertext[1];

                    for (size_t r = policy_type::rounds + 1; r != 1; r -= 2) {
                        L0 ^= permutations[r];
                        R0 ^= policy_type::bff(L0, constants);

                        R0 ^= permutations[r - 1];
                        L0 ^= policy_type::bff(R0, constants);
                    }

                    L0 ^= permutations[1];
                    R0 ^= permutations[0];

                    return {R0, L0};
                }
            };
        }
    }
}

#endif