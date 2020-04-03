//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_POLICY_HPP
#define CRYPTO3_STREEBOG_POLICY_HPP

#include <nil/crypto3/block/streebog.hpp>

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct streebog_policy : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef block::streebog<DigestBits, DigestBits> block_cipher_type;

                    constexpr static const std::size_t digest_bits = DigestBits;
                    typedef static_digest<DigestBits> digest_type;

                    constexpr static const std::size_t state_bits = block_cipher_type::block_bits;
                    constexpr static const std::size_t state_words = block_cipher_type::block_words;
                    typedef typename block_cipher_type::block_type state_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
                            return H0;
                        }
                    };
                };

                template<>
                struct streebog_policy<512> : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef block::streebog<512, 512> block_cipher_type;

                    constexpr static const std::size_t digest_bits = block_cipher_type::block_bits;
                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t state_bits = block_cipher_type::block_bits;
                    constexpr static const std::size_t state_words = block_cipher_type::block_words;
                    typedef typename block_cipher_type::block_type state_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {
                                {0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101,
                                 0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101}};
                            return H0;
                        }
                    };
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_STREEBOG_POLICY_HPP
