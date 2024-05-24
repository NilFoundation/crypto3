//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_MD5_HPP
#define CRYPTO3_BLOCK_MD5_HPP

#include <nil/crypto3/block/detail/md5/md5_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief MD5 block cipher. Stands as a foundation for
             * @ref nil::crypto3::hashes::md5 "MD5" hashes.
             *
             * @ingroup block
             *
             * Encrypt implemented directly from the RFC as found at
             * http://www.faqs.org/rfcs/rfc1321.html
             *
             * Decrypt is a straight-forward inverse
             *
             * In MD5 terminology:
             * - plaintext = AA, BB, CC, and DD
             * - ciphertext = A, B, C, and D
             * - key = M^(i) and X
             */
            class md5 {
                typedef detail::md5_policy policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef policy_type::block_type block_type;

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;
                
                md5(const key_type &k) : key(k) {
                }

                virtual ~md5() {
                    key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(key, plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(key, ciphertext);
                }

            protected:
                key_type key;

                static inline block_type encrypt_block(key_type const &key, block_type const &plaintext) {
                    // Initialize working variables with block
                    word_type a = plaintext[0], b = plaintext[1], c = plaintext[2], d = plaintext[3];

                    // Encipher block
#define CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(aa, bb, cc, dd, fun, k, s, i)                                              \
    {                                                                                                             \
        word_type T =                                                                                             \
            aa + policy_type::fun(bb, cc, dd) + key[policy_type::key_indexes[k]] + policy_type::constants[i - 1]; \
        aa = bb + policy_type::rotl<s>(T);                                                                        \
    }
                    for (unsigned t = 0; t < policy_type::rounds / 4; t += 4) {
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(a, b, c, d, ff, t + 0, 7, t + 1)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(d, a, b, c, ff, t + 1, 12, t + 2)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(c, d, a, b, ff, t + 2, 17, t + 3)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(b, c, d, a, ff, t + 3, 22, t + 4)
                    }
                    for (unsigned t = policy_type::rounds / 4; t < policy_type::rounds / 2; t += 4) {
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(a, b, c, d, gg, t + 0, 5, t + 1)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(d, a, b, c, gg, t + 1, 9, t + 2)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(c, d, a, b, gg, t + 2, 14, t + 3)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(b, c, d, a, gg, t + 3, 20, t + 4)
                    }
                    for (unsigned t = policy_type::rounds / 2; t < 3 * policy_type::rounds / 4; t += 4) {
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(a, b, c, d, hh, t + 0, 4, t + 1)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(d, a, b, c, hh, t + 1, 11, t + 2)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(c, d, a, b, hh, t + 2, 16, t + 3)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(b, c, d, a, hh, t + 3, 23, t + 4)
                    }
                    for (unsigned t = 3 * policy_type::rounds / 4; t < policy_type::rounds; t += 4) {
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(a, b, c, d, ii, t + 0, 6, t + 1)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(d, a, b, c, ii, t + 1, 10, t + 2)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(c, d, a, b, ii, t + 2, 15, t + 3)
                        CRYPTO3_BLOCK_MD5_ENCRYPT_STEP(b, c, d, a, ii, t + 3, 21, t + 4)
                    }

                    return {{a, b, c, d}};
                }

                static inline block_type decrypt_block(key_type const &key, const block_type &ciphertext) {
                    // Initialize working variables with block
                    word_type a = ciphertext[0], b = ciphertext[1], c = ciphertext[2], d = ciphertext[3];

                    // Decipher block
#define CRYPTO3_BLOCK_MD5_DECRYPT_STEP(aa, bb, cc, dd, fun, k, s, i)                                              \
    {                                                                                                             \
        word_type T = policy_type::rotr<s>(aa - bb);                                                              \
        aa = T - policy_type::fun(bb, cc, dd) - key[policy_type::key_indexes[k]] - policy_type::constants[i - 1]; \
    }
                    for (unsigned t = policy_type::rounds; t -= 4, t >= 3 * policy_type::rounds / 4;) {
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(b, c, d, a, ii, t + 3, 21, t + 4)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(c, d, a, b, ii, t + 2, 15, t + 3)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(d, a, b, c, ii, t + 1, 10, t + 2)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(a, b, c, d, ii, t + 0, 6, t + 1)
                    }
                    for (unsigned t = 3 * policy_type::rounds / 4; t -= 4, t >= policy_type::rounds / 2;) {
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(b, c, d, a, hh, t + 3, 23, t + 4)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(c, d, a, b, hh, t + 2, 16, t + 3)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(d, a, b, c, hh, t + 1, 11, t + 2)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(a, b, c, d, hh, t + 0, 4, t + 1)
                    }
                    for (unsigned t = policy_type::rounds / 2; t -= 4, t >= policy_type::rounds / 4;) {
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(b, c, d, a, gg, t + 3, 20, t + 4)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(c, d, a, b, gg, t + 2, 14, t + 3)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(d, a, b, c, gg, t + 1, 9, t + 2)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(a, b, c, d, gg, t + 0, 5, t + 1)
                    }
                    for (unsigned t = policy_type::rounds / 4; t -= 4, t < policy_type::rounds / 4;) {
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(b, c, d, a, ff, t + 3, 22, t + 4)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(c, d, a, b, ff, t + 2, 17, t + 3)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(d, a, b, c, ff, t + 1, 12, t + 2)
                        CRYPTO3_BLOCK_MD5_DECRYPT_STEP(a, b, c, d, ff, t + 0, 7, t + 1)
                    }

                    return {{a, b, c, d}};
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_MD5_HPP
