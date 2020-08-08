//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_CHACHA_POLICY_HPP
#define CRYPTO3_STREAM_CHACHA_POLICY_HPP

#include <boost/endian/conversion.hpp>

#include <boost/container/small_vector.hpp>

#include <nil/crypto3/detail/inline_variable.hpp>

#include <nil/crypto3/stream/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t Rounds, std::size_t IVBits, std::size_t KeyBits,
                         template<typename> class Allocator = std::allocator>
                struct chacha_policy : public basic_functions<32> {
                    typedef typename basic_functions<32>::byte_type byte_type;

                    constexpr static const std::size_t word_bits = basic_functions<32>::word_bits;
                    typedef typename basic_functions<32>::word_type word_type;

                    constexpr static const std::size_t rounds = Rounds;
                    BOOST_STATIC_ASSERT(Rounds % 2 == 0);

                    constexpr static const std::size_t value_bits = CHAR_BIT;
                    typedef byte_type value_type;

                    constexpr static const std::size_t block_values = 1;
                    constexpr static const std::size_t block_bits = block_values * value_bits;
                    typedef boost::container::small_vector<byte_type, block_values> block_type;

                    constexpr static const std::size_t min_key_bits = 16 * CHAR_BIT;
                    constexpr static const std::size_t max_key_bits = 32 * CHAR_BIT;
                    constexpr static const std::size_t key_bits = KeyBits;
                    constexpr static const std::size_t key_size = key_bits / CHAR_BIT;
                    BOOST_STATIC_ASSERT(min_key_bits <= KeyBits <= max_key_bits);
                    BOOST_STATIC_ASSERT(key_size % 16 == 0);
                    typedef std::array<byte_type, key_size> key_type;

                    constexpr static const std::size_t key_schedule_size = 16;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_size * word_bits;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;

                    constexpr static const std::size_t round_constants_size = 4;
                    typedef std::array<word_type, round_constants_size> round_constants_type;

                    CRYPTO3_INLINE_VARIABLE(round_constants_type, tau,
                                            ({0x61707865, 0x3120646e, 0x79622d36, 0x6b206574}));
                    CRYPTO3_INLINE_VARIABLE(round_constants_type, sigma,
                                            ({0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}));

                    constexpr static const std::size_t iv_bits = IVBits;
                    constexpr static const std::size_t iv_size = IVBits / CHAR_BIT;
                    typedef std::array<byte_type, iv_size> iv_type;
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHACHA_POLICY_HPP
