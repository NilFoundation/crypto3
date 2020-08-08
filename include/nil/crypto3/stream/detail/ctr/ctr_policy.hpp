//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_CTR_POLICY_HPP
#define CRYPTO3_STREAM_CTR_POLICY_HPP

#include <boost/endian/conversion.hpp>

#include <boost/container/small_vector.hpp>

#include <nil/crypto3/detail/inline_variable.hpp>

#include <nil/crypto3/stream/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<typename BlockCipher, std::size_t CtrBits>
                struct ctr_policy : public basic_functions<32> {
                    typedef BlockCipher cipher_type;

                    typedef typename basic_functions<32>::byte_type byte_type;

                    constexpr static const std::size_t word_bits = basic_functions<32>::word_bits;
                    typedef typename basic_functions<32>::word_type word_type;

                    constexpr static const std::size_t block_bits = cipher_type::block_bits;
                    typedef typename cipher_type::block_type block_type;

                    constexpr static const std::size_t key_bits = cipher_type::key_bits;
                    constexpr static const std::size_t min_key_bits = key_bits;
                    constexpr static const std::size_t max_key_bits = key_bits;
                    typedef typename cipher_type::key_type key_type;

                    constexpr static const std::size_t round_constants_size = 4;
                    typedef std::array<word_type, round_constants_size> round_constants_type;

                    constexpr static const std::size_t iv_bits = block_bits;
                    constexpr static const std::size_t iv_size = iv_bits / CHAR_BIT;
                    typedef std::array<byte_type, iv_size> iv_type;
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CTR_POLICY_HPP
