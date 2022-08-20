//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_R1CS_POWERS_OF_TAU_HPP
#define CRYPTO3_R1CS_POWERS_OF_TAU_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/detail/basic_policy.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/helpers.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/private_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/public_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/result.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/marshalling/algebra/types/fast_curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
// #include <nil/crypto3/random/chacha.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, unsigned Tau_Powers_Length>
                class powers_of_tau {
                    typedef detail::powers_of_tau_basic_policy<CurveType, Tau_Powers_Length> policy_type;
                    typedef CurveType curve_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;
                    typedef typename CurveType::g1_type<> g1_type;
                    typedef typename g1_type::value_type g1_value_type;
                    typedef typename CurveType::g2_type<> g2_type;
                    typedef typename g2_type::value_type g2_value_type;
                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::accumulator_type accumulator_type;
                    typedef powers_of_tau_helpers<CurveType, Tau_Powers_Length> helpers_type;

                enum parameter_personalization{
                    tau_personalization,
                    alpha_personalization,
                    beta_personalization
                };

                public:
                    static accumulator_type initial_accumulator() {
                        return accumulator_type();
                    }
                
                    static public_key_type contribute_randomness(accumulator_type &acc) {
                        std::vector<std::uint8_t> transcript = helpers_type::compute_transcript(acc);

                        auto kp = helpers_type::generate_keypair(transcript);
                        acc.transform(kp.second);
                        return kp.first;
                    }

                    // Filecoin claims this isn't necessary btw
                    static public_key_type apply_randomness_beacon(accumulator_type &acc, const std::vector<std::uint8_t> &beacon) {
                        std::size_t n = 42;
                        std::vector<std::uint8_t> cur_hash = beacon;
                        for(std::size_t i = 0; i < (1 << n); ++i) {
                            std::vector<std::uint8_t> hash = nil::crypto3::hash<hashes::sha2<256>>(cur_hash);
                            cur_hash = hash;
                        }

                        // should be chacha rng
                        boost::random::mt19937 gen;
                        gen.seed(cur_hash[0]);
                        
                        std::vector<std::uint8_t> transcript = helpers_type::compute_transcript(acc);

                        auto kp = helpers_type::generate_keypair(transcript, gen);
                        acc.transform(kp.second);
                        return kp.first;
                    }

                    static bool verify_contribution(const accumulator_type &before,
                                                    const accumulator_type &after,
                                                    const public_key_type &public_key) {
                        std::vector<std::uint8_t> transcript = helpers_type::compute_transcript(before);
                        return helpers_type::verify_contribution_with_transcript(before,
                                                            after,
                                                            public_key,
                                                            transcript);
                    }

                    static bool verify_beacon_contribution(const accumulator_type &before,
                                                    const accumulator_type &after,
                                                    const std::vector<std::uint8_t> &beacon) {
                        std::size_t n = 42;
                        std::vector<std::uint8_t> cur_hash = beacon;
                        for(std::size_t i = 0; i < (1 << n); ++i) {
                            std::vector<std::uint8_t> hash = nil::crypto3::hash<hashes::sha2<256>>(cur_hash);
                            cur_hash = hash;
                        }

                        // should be chacha rng
                        boost::random::mt19937 gen;
                        gen.seed(cur_hash[0]);
                        
                        std::vector<std::uint8_t> transcript = helpers_type::compute_transcript(before);

                        auto kp = helpers_type::generate_keypair(transcript, gen);

                        return helpers_type::verify_contribution_with_transcript(before,
                                                            after,
                                                            kp.first,
                                                            transcript);
                    }

                    static powers_of_tau_result<curve_type> finalize(const accumulator_type &acc) {
                        auto alpha_g1 = acc.alpha_tau_powers_g1[0];
                        auto beta_g1 = acc.beta_tau_powers_g1[0];
                        auto beta_g2 = acc.beta_g2; 
                        
                        std::vector<g1_value_type> coeffs_g1 = helpers_type::evaluate_lagrange_polynomials(acc.tau_powers_g1, policy_type::tau_powers_length);
                        
                        std::vector<g2_value_type> coeffs_g2 = helpers_type::evaluate_lagrange_polynomials(acc.tau_powers_g2, policy_type::tau_powers_length);
                        
                        std::vector<g1_value_type> alpha_coeffs_g1 = helpers_type::evaluate_lagrange_polynomials(acc.alpha_tau_powers_g1, policy_type::tau_powers_length);
                        
                        std::vector<g1_value_type> beta_coeffs_g1 = helpers_type::evaluate_lagrange_polynomials(acc.beta_tau_powers_g1, policy_type::tau_powers_length);
                        
                        std::vector<g1_value_type> h;
                        std::size_t degree = Tau_Powers_Length;
                        BOOST_ASSERT(degree == math::detail::power_of_two(degree));
                        for(std::size_t i=0; i < degree-1; ++i) {
                            h.emplace_back(acc.tau_powers_g1[i + degree] - acc.tau_powers_g1[i]);
                        }
                        return powers_of_tau_result<curve_type> {
                            alpha_g1,
                            beta_g1,
                            beta_g2,
                            coeffs_g1,
                            coeffs_g2,
                            alpha_coeffs_g1,
                            beta_coeffs_g1,
                            h
                        };
                    }
                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_POWERS_OF_TAU_HPP
