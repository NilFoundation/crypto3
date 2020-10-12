//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_TIGER_POLICY_HPP
#define CRYPTO3_TIGER_POLICY_HPP

#include <nil/crypto3/hash/detail/tiger/tiger_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits, std::size_t Passes>
                struct tiger_policy : public tiger_functions<DigestBits> {
                    typedef typename tiger_functions<DigestBits>::byte_type byte_type;

                    constexpr static const std::size_t word_bits = tiger_functions<DigestBits>::word_bits;
                    typedef typename tiger_functions<DigestBits>::word_type word_type;

                    constexpr static const std::size_t passes = Passes;

                    typedef typename stream_endian::little_octet_big_bit digest_endian;

                    constexpr static const std::size_t digest_bits = DigestBits;
                    typedef static_digest<DigestBits> digest_type;

                    constexpr static const std::size_t pkcs_id_size = 0;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {};

                    constexpr static const std::size_t state_bits = tiger_functions<DigestBits>::state_bits;
                    constexpr static const std::size_t state_words = tiger_functions<DigestBits>::state_words;
                    typedef typename tiger_functions<DigestBits>::state_type state_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {
                                {0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187}};
                            return H0;
                        }
                    };
                };

                template<>
                struct tiger_policy<192, 3> : public tiger_functions<192> {
                    constexpr static const std::size_t digest_bits = 192;
                    typedef static_digest<digest_bits> digest_type;

                    typedef typename tiger_functions<digest_bits>::byte_type byte_type;

                    constexpr static const std::size_t word_bits = tiger_functions<digest_bits>::word_bits;
                    typedef typename tiger_functions<digest_bits>::word_type word_type;

                    constexpr static const std::size_t passes = 3;

                    typedef typename stream_endian::little_octet_big_bit digest_endian;

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x29, 0x30, 0x0D, 0x06, 0x09, 0x2B,
                                                                   0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0C,
                                                                   0x02, 0x05, 0x00, 0x04, 0x18};

                    constexpr static const std::size_t state_bits = tiger_functions<digest_bits>::state_bits;
                    constexpr static const std::size_t state_words = tiger_functions<digest_bits>::state_words;
                    typedef typename tiger_functions<digest_bits>::state_type state_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {
                                {0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187}};
                            return H0;
                        }
                    };
                };

                template<std::size_t DigestBits, std::size_t Passes>
                constexpr typename tiger_policy<DigestBits, Passes>::pkcs_id_type const
                    tiger_policy<DigestBits, Passes>::pkcs_id;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TIGER_POLICY_HPP
