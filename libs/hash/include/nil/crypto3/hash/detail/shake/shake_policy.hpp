//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_SHAKE_POLICY_HPP
#define CRYPTO3_SHAKE_POLICY_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

#include <array>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t HalfCapacity>
                struct basic_shake_policy : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 0;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {};
                };

                template<>
                struct basic_shake_policy<256> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x0C, 0x05, 0x00, 0x04, 0x1C};  // fix-me: incorrect pcks_id (but, oid is true)
                };

                template<>
                struct basic_shake_policy<128> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                   0x0B, 0x05, 0x00, 0x04, 0x20};   // fix-me: incorrect pcks_id (but, oid is true)
                };

                
                template<std::size_t HalfCapacity>
                constexpr
                    typename basic_shake_policy<HalfCapacity>::pkcs_id_type const basic_shake_policy<HalfCapacity>::pkcs_id;

                template<std::size_t HalfCapacity>
                struct shake_policy : public basic_shake_policy<HalfCapacity> {

                    typedef basic_shake_policy<HalfCapacity> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t half_capacity = HalfCapacity;

                    constexpr static const std::size_t state_bits = 1600;
                    constexpr static const std::size_t state_words = state_bits / word_bits;
                    typedef typename std::array<word_type, state_words> state_type;

                    constexpr static const std::size_t block_bits = state_bits - 2 * half_capacity;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t pkcs_id_size = policy_type::pkcs_id_size;
                    constexpr static const std::size_t pkcs_id_bits = policy_type::pkcs_id_bits;
                    typedef typename policy_type::pkcs_id_type pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = policy_type::pkcs_id;

                    constexpr static const std::size_t length_bits = 0;

                    typedef typename stream_endian::little_octet_big_bit digest_endian;

                    constexpr static const std::size_t rounds = 24;

                    struct iv_generator {
                        static state_type generate() {
                            return keccak_1600_policy<HalfCapacity>::iv_generator::generate();
                        }
                    };
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_POLICY_HPP
