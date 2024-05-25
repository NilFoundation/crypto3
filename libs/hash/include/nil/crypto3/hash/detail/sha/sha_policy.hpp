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

#ifndef CRYPTO3_HASH_DETAIL_SHA_POLICY_HPP
#define CRYPTO3_HASH_DETAIL_SHA_POLICY_HPP

#include <nil/crypto3/block/shacal.hpp>

#include <nil/crypto3/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                struct sha_policy {
                    typedef block::shacal0 block_cipher_type;

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

                    constexpr static const std::size_t digest_bits = 160;
                    constexpr static const std::uint8_t ieee1363_hash_id = 0x33;

                    typedef static_digest<digest_bits> digest_type;
                    typedef std::array<std::uint8_t, 15> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
                                                                   0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};

                    struct iv_generator {
                        state_type const &operator()() const {
                            // First 4 words are the same as MD4
                            static state_type const H0 = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}};
                            return H0;
                        }
                    };
                };

                typedef sha_policy sha0_policy;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_SHA_POLICY_HPP
