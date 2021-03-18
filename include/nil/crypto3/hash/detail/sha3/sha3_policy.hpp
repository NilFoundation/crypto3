//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_SHA3_POLICY_HPP
#define CRYPTO3_SHA3_POLICY_HPP

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <array>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits>
                struct basic_sha3_policy : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 0;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {};
                };

                template<>
                struct basic_sha3_policy<224> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x07, 0x05, 0x00, 0x04, 0x1C};
                };

                template<>
                struct basic_sha3_policy<256> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x08, 0x05, 0x00, 0x04, 0x20};
                };

                template<>
                struct basic_sha3_policy<384> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x09, 0x05, 0x00, 0x04, 0x30};
                };

                template<>
                struct basic_sha3_policy<512> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x0A, 0x05, 0x00, 0x04, 0x40};
                };

                template<std::size_t DigestBits>
                constexpr
                    typename basic_sha3_policy<DigestBits>::pkcs_id_type const basic_sha3_policy<DigestBits>::pkcs_id;

                template<std::size_t DigestBits>
                struct sha3_policy : public basic_sha3_policy<DigestBits> {

                    typedef basic_sha3_policy<DigestBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t digest_bits = DigestBits;
                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t state_bits = 1600;
                    constexpr static const std::size_t state_words = state_bits / word_bits;
                    typedef typename std::array<word_type, state_words> state_type;

                    constexpr static const std::size_t block_bits = state_bits - 2 * digest_bits;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t pkcs_id_size = policy_type::pkcs_id_size;
                    constexpr static const std::size_t pkcs_id_bits = policy_type::pkcs_id_bits;
                    typedef typename policy_type::pkcs_id_type pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = policy_type::pkcs_id;

                    constexpr static const std::size_t length_bits = 0;

                    typedef typename stream_endian::big_octet_big_bit digest_endian;

                    constexpr static const std::size_t rounds = 24;

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                                                          UINT64_C(0x0000000000000000)};
                            return H0;
                        }
                    };
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_POLICY_HPP
