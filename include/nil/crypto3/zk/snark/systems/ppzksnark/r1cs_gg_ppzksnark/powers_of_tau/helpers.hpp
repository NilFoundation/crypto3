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

#ifndef CRYPTO3_R1CS_POWERS_OF_TAU_HELPERS_HPP
#define CRYPTO3_R1CS_POWERS_OF_TAU_HELPERS_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/detail/basic_policy.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/private_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/public_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/accumulator.hpp>

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
#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/random/chacha.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, unsigned Tau_Powers_Length>
                class powers_of_tau_helpers {
                    typedef detail::powers_of_tau_basic_policy<CurveType, Tau_Powers_Length> policy_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;
                    typedef typename CurveType::g1_type<> g1_type;
                    typedef typename g1_type::value_type g1_value_type;
                    typedef typename CurveType::g2_type<> g2_type;
                    typedef typename g2_type::value_type g2_value_type;
                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::accumulator_type accumulator_type;

                enum parameter_personalization{
                    tau_personalization,
                    alpha_personalization,
                    beta_personalization
                };

                public:                
                    static bool verify_contribution_with_transcript(const accumulator_type &before,
                                                            const accumulator_type &after,
                                                            const public_key_type &public_key,
                                                            const std::vector<std::uint8_t> &transcript) {
                        auto tau_g2_s = compute_g2_s(public_key.tau_pok.g1_s, public_key.tau_pok.g1_s_x, transcript, tau_personalization);
                        auto alpha_g2_s = compute_g2_s(public_key.alpha_pok.g1_s, public_key.alpha_pok.g1_s_x, transcript, alpha_personalization);
                        auto beta_g2_s = compute_g2_s(public_key.beta_pok.g1_s, public_key.beta_pok.g1_s_x, transcript, beta_personalization);
                        
                        // Verify the proofs of knowledge of tau, alpha and beta
                        if(!verify_pok(public_key.tau_pok, tau_g2_s)) {
                            return false;
                        }
                        if(!verify_pok(public_key.alpha_pok, alpha_g2_s)) {
                            return false;
                        }
                        if(!verify_pok(public_key.beta_pok, beta_g2_s)) {
                            return false;
                        }

                        // Check the correctness of the generators fot tau powers
                        if(after.tau_powers_g1[0] != g1_value_type::one()) {
                            return false;
                        }
                        if(after.tau_powers_g2[0] != g2_value_type::one()) {
                            return false;
                        }

                        // Did the participant multiply the previous tau by the new one?
                        if(!is_same_ratio(std::make_pair(before.tau_powers_g1[1], after.tau_powers_g1[1]),
                                          std::make_pair(tau_g2_s, public_key.tau_pok.g2_s_x))) {
                            return false;
                        }

                        // Did the participant multiply the previous alpha by the new one?
                        if(!is_same_ratio(std::make_pair(before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]),
                                          std::make_pair(alpha_g2_s, public_key.alpha_pok.g2_s_x))) {
                            return false;
                        }

                        // Did the participant multiply the previous beta by the new one?
                        if(!is_same_ratio(std::make_pair(before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
                                          std::make_pair(beta_g2_s, public_key.beta_pok.g2_s_x))) {
                            return false;
                        }

                        if(!is_same_ratio(std::make_pair(before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
                                          std::make_pair(before.beta_g2, after.beta_g2))) {
                            return false;
                        }

                        // Are the powers of tau correct?
                        if(!is_same_ratio(power_pairs(after.tau_powers_g1), std::make_pair(after.tau_powers_g2[0], after.tau_powers_g2[1]))) {
                            return false;
                        }
                        if(!is_same_ratio(std::make_pair(after.tau_powers_g1[0], after.tau_powers_g1[1]), power_pairs(after.tau_powers_g2))) {
                            return false;
                        }
                        if(!is_same_ratio(power_pairs(after.alpha_tau_powers_g1), std::make_pair(after.tau_powers_g2[0], after.tau_powers_g2[1]))) {
                            return false;
                        }
                        if(!is_same_ratio(power_pairs(after.beta_tau_powers_g1), std::make_pair(after.tau_powers_g2[0], after.tau_powers_g2[1]))) {
                            return false;
                        }

                        return true;
                    }

                    static std::vector<std::uint8_t> serialize_accumulator(const accumulator_type &acc) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val = nil::crypto3::marshalling::types::fill_powers_of_tau_accumulator<accumulator_type, endianness>(acc);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);
                        return blob;
                    }

                    static std::vector<std::uint8_t> compute_transcript(const accumulator_type &acc) {
                        auto acc_blob = serialize_accumulator(acc);
                        return nil::crypto3::hash<hashes::blake2b<512>>(acc_blob);
                    }

                    template<typename RNG = boost::random_device>
                    static std::pair<public_key_type, private_key_type> generate_keypair(const std::vector<std::uint8_t> &transcript, RNG&& rng = boost::random_device()) {
                        typename scalar_field_type::value_type tau =
                            algebra::random_element<scalar_field_type>(rng);
                        typename scalar_field_type::value_type alpha =
                            algebra::random_element<scalar_field_type>(rng);
                        typename scalar_field_type::value_type beta =
                            algebra::random_element<scalar_field_type>(rng);

                        auto tau_pok = construct_pok(tau, transcript, tau_personalization, rng);
                        auto alpha_pok = construct_pok(alpha, transcript, alpha_personalization, rng);
                        auto beta_pok = construct_pok(beta, transcript, beta_personalization, rng);

                        public_key_type public_key {
                            tau_pok,
                            alpha_pok,
                            beta_pok
                        };

                        private_key_type private_key {
                            tau,
                            alpha,
                            beta
                        };

                        return {
                            public_key,
                            private_key
                        };
                    }

                    template<typename RNG = boost::random_device>
                    static proof_of_knowledge<CurveType>
                        construct_pok(scalar_field_value_type x,
                           const std::vector<std::uint8_t> &transcript,
                           std::uint8_t personalization,
                           RNG&& rng = boost::random_device()) {
                            const g1_value_type g1_s = algebra::random_element<g1_type>(rng);
                            const g1_value_type g1_s_x = x * g1_s;
                            auto g2_s = compute_g2_s(g1_s, g1_s_x, transcript, personalization);
                            auto g2_s_x = x * g2_s;
                            return proof_of_knowledge<CurveType> { g1_s, g1_s_x, g2_s_x };
                    }

                    static bool verify_pok(const proof_of_knowledge<CurveType> &pok,
                                    const g2_value_type g2_s) {
                        return is_same_ratio(std::make_pair(pok.g1_s, pok.g1_s_x), std::make_pair(g2_s, pok.g2_s_x));
                    }

                    static bool is_same_ratio(std::pair<g1_value_type, g1_value_type> g1_pair, std::pair<g2_value_type, g2_value_type> g2_pair) {
                        
                        return algebra::pair_reduced<CurveType>(g1_pair.first, g2_pair.second) == algebra::pair_reduced<CurveType>(g1_pair.second, g2_pair.first);
                    }

                    static g2_value_type compute_g2_s(g1_value_type g1_s, g1_value_type g1_s_x,
                                                      const std::vector<std::uint8_t> transcript,
                                                      std::uint8_t personalization) {

                        std::vector<std::uint8_t> personalization_transcript_g1s_g1sx; 
                        
                        personalization_transcript_g1s_g1sx.emplace_back(personalization);

                        std::copy(std::cbegin(transcript),
                                    std::cend(transcript),
                                    std::back_inserter(personalization_transcript_g1s_g1sx));
                        
                        auto g1_s_blob = serialize_g1_uncompressed(g1_s);
                        std::copy(std::cbegin(g1_s_blob),
                                    std::cend(g1_s_blob),
                                    std::back_inserter(g1_s_blob));
                        
                        auto g1_s_x_blob = serialize_g1_uncompressed(g1_s_x);
                        std::copy(std::cbegin(g1_s_x_blob),
                                    std::cend(g1_s_x_blob),
                                    std::back_inserter(g1_s_x_blob));
                        // In the rust version they truncate the blake2b hash to 32 bytes.
                        // I'm assuming this is equivalent.
                        std::vector<std::uint8_t> hash = nil::crypto3::hash<hashes::blake2b<256>>(personalization_transcript_g1s_g1sx);
                        
                        // in the rust version chacha rng is used, but chacha rng is broken right now.
                        // the current solution is obviously not secure at all, but it's just a placeholder
                        boost::random::mt19937 gen;
                        // random::chacha gen;
                        gen.seed(hash[0]);
                        // gen.seed(hash.begin(), hash.end());
                        return algebra::random_element<g2_type>(gen);
                    }

                    static std::vector<std::uint8_t> serialize_g1_uncompressed(g1_value_type point) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val = nil::crypto3::marshalling::types::fill_fast_curve_element<g1_type, endianness>(point);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);
                        return blob;
                    }

                    // Computes a random linear combination over v1/v2.
                    //
                    // Checking that many pairs of elements are exponentiated by
                    // the same `x` can be achieved (with high probability) with
                    // the following technique:
                    //
                    // Given v1 = [a, b, c] and v2 = [as, bs, cs], compute
                    // (a*r1 + b*r2 + c*r3, (as)*r1 + (bs)*r2 + (cs)*r3) for some
                    // random r1, r2, r3. Given (g, g^s)...
                    //
                    // e(g, (as)*r1 + (bs)*r2 + (cs)*r3) = e(g^s, a*r1 + b*r2 + c*r3)
                    //
                    // ... with high probability.

                    template<typename PointIterator>
                    static std::pair<typename PointIterator::value_type, typename PointIterator::value_type> merge_pairs(
                        const PointIterator &v1_begin,
                        const PointIterator &v1_end,
                        const PointIterator &v2_begin,
                        const PointIterator &v2_end) {
                        
                        BOOST_ASSERT(std::distance(v1_begin, v1_end) == std::distance(v2_begin, v2_end));

                        std::size_t size = std::distance(v1_begin, v1_end);
                        std::vector<scalar_field_value_type> r;
                        for(std::size_t i = 0; i < size; ++i) {
                            r.emplace_back(algebra::random_element<scalar_field_type>());
                        }

                        typename PointIterator::value_type res1 =
                            algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                v1_begin,
                                v1_end,
                                r.begin(),
                                r.end(),
                                1);

                       typename PointIterator::value_type res2 =
                            algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                v2_begin,
                                v2_end,
                                r.begin(),
                                r.end(),
                                1);

                        return std::make_pair(res1, res2);
                    }

                    // Construct a single pair (s, s^x) for a vector of
                    // the form [1, x, x^2, x^3, ...].
                    template<typename GroupValueType>
                    static std::pair<GroupValueType, GroupValueType> power_pairs(
                        const std::vector<GroupValueType> & v) {

                        return merge_pairs(v.begin(), v.end() - 1, v.begin() + 1, v.end());
                    }

                    
                    template<typename GroupValueType>
                    static std::vector<GroupValueType>
                     evaluate_lagrange_polynomials(const std::vector<GroupValueType> &powers, std::size_t degree) {
                        
                        BOOST_ASSERT(degree <= powers.size());
                        BOOST_ASSERT(degree == math::detail::power_of_two(degree));
                        
                        std::vector<GroupValueType> res(powers.begin(), powers.begin() + degree);
                        auto domain = math::make_evaluation_domain<scalar_field_type, GroupValueType>(degree);
                        domain->inverse_fft(res);
                        return res;
                    }

                    static std::size_t power_of_two(std::size_t n) {
                        n--;
                        n |= n >> 1;
                        n |= n >> 2;
                        n |= n >> 4;
                        n |= n >> 8;
                        n |= n >> 16;
                        n++;

                        return n;
                    }


                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_POWERS_OF_TAU_HELPERS_HPP
