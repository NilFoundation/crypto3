//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_SIPHASH_FUNCTIONS_HPP
#define CRYPTO3_MAC_SIPHASH_FUNCTIONS_HPP

#include <boost/container/static_vector.hpp>
#include <boost/integer.hpp>

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
#pragma clang loop unroll(full)
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
