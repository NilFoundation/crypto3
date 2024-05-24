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

#ifndef CRYPTO3_MAC_SIPHASH_FUNCTIONS_HPP
#define CRYPTO3_MAC_SIPHASH_FUNCTIONS_HPP

#include <boost/integer.hpp>
#include <boost/container/static_vector.hpp>

#include <nil/crypto3/mac/detail/siphash/siphash_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<std::size_t Rounds, std::size_t FinalRounds>
                struct siphash_functions : public siphash_policy<Rounds, FinalRounds> {
                    typedef siphash_policy<Rounds, FinalRounds> policy_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;
                    constexpr static const std::size_t final_rounds = policy_type::final_rounds;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    constexpr static const std::size_t key_words = policy_type::key_words;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    template<std::size_t InternalRounds>
                    void sip_rounds(key_schedule_type& V, word_type M) {
                        word_type V0 = V[0], V1 = V[1], V2 = V[2], V3 = V[3];

                        V3 ^= M;

                        for (size_t i = 0; i != InternalRounds; ++i) {
                            V0 += V1;
                            V2 += V3;
                            V1 = policy_type::template rotl<13>(V1);
                            V3 = policy_type::template rotl<16>(V3);
                            V1 ^= V0;
                            V3 ^= V2;
                            V0 = policy_type::template rotl<32>(V0);

                            V2 += V1;
                            V0 += V3;
                            V1 = policy_type::template rotl<17>(V1);
                            V3 = policy_type::template rotl<21>(V3);
                            V1 ^= V2;
                            V3 ^= V0;
                            V2 = policy_type::template rotl<32>(V2);
                        }
                        V0 ^= M;

                        V[0] = V0;
                        V[1] = V1;
                        V[2] = V2;
                        V[3] = V3;
                    }
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SIPHASH_POLICY_HPP
