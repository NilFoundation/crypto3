//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

                    constexpr static const std::size_t pkcs_id_size = 19;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x29, 0x30, 0x0D, 0x06, 0x09, 0x2B,
                                                                   0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0C,
                                                                   0x02, 0x05, 0x00, 0x04, 0x18};

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

                template<std::size_t DigestBits, std::size_t Passes>
                constexpr typename tiger_policy<DigestBits, Passes>::pkcs_id_type const
                    tiger_policy<DigestBits, Passes>::pkcs_id;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TIGER_POLICY_HPP
