//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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
