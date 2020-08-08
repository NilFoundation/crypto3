//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_SIPHASH_POLICY_HPP
#define CRYPTO3_MAC_SIPHASH_POLICY_HPP

#include <boost/container/static_vector.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/integer.hpp>

#include <nil/crypto3/mac/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<std::size_t Rounds, std::size_t FinalRounds>
                struct siphash_policy : public basic_functions<64> {
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t word_bits = basic_functions<64>::word_bits;
                    typedef typename basic_functions<64>::word_type word_type;

                    constexpr static const std::size_t rounds = Rounds;
                    constexpr static const std::size_t final_rounds = FinalRounds;

                    constexpr static const std::size_t key_words = 2;
                    constexpr static const std::size_t key_bits = key_words * word_bits;
                    typedef std::array<word_type, key_words> key_type;

                    constexpr static const std::size_t key_schedule_size = 4;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SIPHASH_POLICY_HPP
