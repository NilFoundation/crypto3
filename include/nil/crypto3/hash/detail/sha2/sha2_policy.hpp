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

#ifndef CRYPTO3_HASH_DETAIL_SHA2_POLICY_HPP
#define CRYPTO3_HASH_DETAIL_SHA2_POLICY_HPP

#include <nil/crypto3/block/shacal2.hpp>

#include <nil/crypto3/detail/static_digest.hpp>

#include <array>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                template<std::size_t CipherVersion>
                struct basic_sha2_policy {

                    constexpr static const std::size_t cipher_version = CipherVersion;
                    typedef block::shacal2<cipher_version> block_cipher_type;

                    constexpr static const std::size_t word_bits = block_cipher_type::word_bits;
                    typedef typename block_cipher_type::word_type word_type;

                    constexpr static const std::size_t state_bits = block_cipher_type::block_bits;
                    constexpr static const std::size_t state_words = block_cipher_type::block_words;
                    typedef typename block_cipher_type::block_type state_type;

                    constexpr static const std::size_t block_bits = block_cipher_type::key_bits;
                    constexpr static const std::size_t block_words = block_cipher_type::key_words;
                    typedef typename block_cipher_type::key_type block_type;

                    constexpr static const std::size_t length_bits = word_bits * 2;

                    typedef typename stream_endian::big_octet_big_bit digest_endian;
                };

                template<std::size_t Version>
                struct sha2_policy;

                template<>
                struct sha2_policy<224> : public basic_sha2_policy<256> {

                    constexpr static const std::size_t digest_bits = 224;
                    constexpr static const std::uint8_t ieee1363_hash_id = 0x38;

                    constexpr static const std::size_t pkcs_id_size = 0;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {};

                    typedef static_digest<digest_bits> digest_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {{0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31,
                                                           0x68581511, 0x64f98fa7, 0xbefa4fa4}};
                            return H0;
                        }
                    };
                };

                template<>
                struct sha2_policy<256> : public basic_sha2_policy<256> {

                    constexpr static const std::size_t digest_bits = 256;
                    constexpr static const std::uint8_t ieee1363_hash_id = 0x34;

                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x04, 0x05, 0x00, 0x04, 0x20};

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                                                           0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
                            return H0;
                        }
                    };
                };

                template<>
                struct sha2_policy<384> : public basic_sha2_policy<512> {

                    constexpr static const std::size_t digest_bits = 384;
                    constexpr static const std::uint8_t ieee1363_hash_id = 0x36;

                    constexpr static const std::size_t pkcs_id_size = 0;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {};

                    typedef static_digest<digest_bits> digest_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {{UINT64_C(0xcbbb9d5dc1059ed8), UINT64_C(0x629a292a367cd507),
                                                           UINT64_C(0x9159015a3070dd17), UINT64_C(0x152fecd8f70e5939),
                                                           UINT64_C(0x67332667ffc00b31), UINT64_C(0x8eb44a8768581511),
                                                           UINT64_C(0xdb0c2e0d64f98fa7), UINT64_C(0x47b5481dbefa4fa4)}};
                            return H0;
                        }
                    };
                };

                template<>
                struct sha2_policy<512> : public basic_sha2_policy<512> {

                    constexpr static const std::size_t digest_bits = 512;
                    constexpr static const std::uint8_t ieee1363_hash_id = 0x35;

                    typedef static_digest<digest_bits> digest_type;
                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x04, 0x05, 0x00, 0x04, 0x40};

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {{UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
                                                           UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
                                                           UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
                                                           UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)}};
                            return H0;
                        }
                    };
                };

                constexpr typename sha2_policy<224>::pkcs_id_type const sha2_policy<224>::pkcs_id;

                constexpr typename sha2_policy<256>::pkcs_id_type const sha2_policy<256>::pkcs_id;

                constexpr typename sha2_policy<384>::pkcs_id_type const sha2_policy<384>::pkcs_id;

                constexpr typename sha2_policy<512>::pkcs_id_type const sha2_policy<512>::pkcs_id;

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_SHA2_POLICY_HPP
