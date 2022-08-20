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

#ifndef CRYPTO3_R1CS_MPC_GENERATOR_HELPERS_HPP
#define CRYPTO3_R1CS_MPC_GENERATOR_HELPERS_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/private_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/public_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/mpc_params.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <vector>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/r1cs.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/mpc/public_key.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/random/chacha.hpp>


namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_mpc_generator_helpers {
                    typedef CurveType curve_type;
                    typedef r1cs_gg_ppzksnark<curve_type> proving_scheme_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_private_key<curve_type> private_key_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_public_key<curve_type> public_key_type;
                    typedef r1cs_gg_ppzksnark_mpc_params<curve_type> mpc_params_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using kc_type = commitments::knowledge_commitment<g2_type, g1_type>;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using kc_value_type = typename kc_type::value_type;
                    using scalar_field_type = typename curve_type::scalar_field_type; 
                    using scalar_field_value_type = typename scalar_field_type::value_type; 

                public:
                    static std::pair<public_key_type, private_key_type> generate_keypair(const g1_value_type & previous_delta,
                                                                                  const std::vector<std::uint8_t> &transcript) {
                        private_key_type sk {
                            algebra::random_element<scalar_field_type>()
                        };
                        
                        auto delta_pok = construct_pok(sk.delta, transcript);
                        public_key_type pk {
                            sk.delta * previous_delta,
                            delta_pok
                        };

                        return {pk, sk};
                    }

                    static proof_of_knowledge<CurveType>
                        construct_pok(scalar_field_value_type x,
                           const std::vector<std::uint8_t> &transcript) {
                            const g1_value_type g1_s = algebra::random_element<g1_type>(boost::random_device());
                            const g1_value_type g1_s_x = x * g1_s;
                            auto g2_s = compute_g2_s(g1_s, g1_s_x, transcript);
                            auto g2_s_x = x * g2_s;
                            return proof_of_knowledge<CurveType> { g1_s, g1_s_x, g2_s_x };
                    }

                    static std::vector<std::uint8_t> serialize_public_key(const public_key_type &pubkey) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val = nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_mpc_generator_public_key<public_key_type, endianness>(pubkey);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);
                        return blob;
                    }

                    static std::vector<std::uint8_t> serialize_constraint_system(const typename proving_scheme_type::constraint_system_type &constraint_system) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val = nil::crypto3::marshalling::types::fill_r1cs_constraint_system<typename proving_scheme_type::constraint_system_type, endianness>(constraint_system);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);
                        return blob;
                    }

                    static std::vector<std::uint8_t> compute_transcript(const typename proving_scheme_type::constraint_system_type &constraint_system) {
                        auto blob = serialize_constraint_system(constraint_system);
                        return nil::crypto3::hash<hashes::blake2b<512>>(blob);
                    }

                    static std::vector<std::uint8_t> compute_transcript(const typename proving_scheme_type::constraint_system_type &constraint_system, const public_key_type &pubkey) {
                        auto cs_blob = serialize_constraint_system(constraint_system);
                        auto pk_blob = serialize_public_key(pubkey);
                        std::vector<std::uint8_t> cs_pk_blob;
                        std::copy(
                            std::cbegin(cs_blob),
                            std::cend(cs_blob), 
                            std::back_inserter(cs_pk_blob)
                        );
                        std::copy(
                            std::cbegin(pk_blob),
                            std::cend(pk_blob), 
                            std::back_inserter(cs_pk_blob)
                        );
                        return nil::crypto3::hash<hashes::blake2b<512>>(cs_pk_blob);
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

                    static bool verify_pok(const proof_of_knowledge<CurveType> &pok,
                                           const g2_value_type g2_s) {
                        return is_same_ratio(std::make_pair(pok.g1_s, pok.g1_s_x), std::make_pair(g2_s, pok.g2_s_x));
                    }

                    static bool is_same_ratio(std::pair<g1_value_type, g1_value_type> g1_pair, std::pair<g2_value_type, g2_value_type> g2_pair) {
                        
                        return algebra::pair_reduced<CurveType>(g1_pair.first, g2_pair.second) == algebra::pair_reduced<CurveType>(g1_pair.second, g2_pair.first);
                    }

                    static g2_value_type compute_g2_s(g1_value_type g1_s, g1_value_type g1_s_x, const std::vector<std::uint8_t> &transcript) {

                        std::vector<std::uint8_t> transcript_g1s_g1sx; 
                        
                        std::copy(std::cbegin(transcript),
                                    std::cend(transcript),
                                    std::back_inserter(transcript_g1s_g1sx));
                        
                        auto g1_s_blob = serialize_g1_uncompressed(g1_s);
                        std::copy(std::cbegin(g1_s_blob),
                                    std::cend(g1_s_blob),
                                    std::back_inserter(g1_s_blob));
                        
                        auto g1_s_x_blob = serialize_g1_uncompressed(g1_s_x);
                        std::copy(std::cbegin(g1_s_x_blob),
                                    std::cend(g1_s_x_blob),
                                    std::back_inserter(g1_s_x_blob));

                        std::vector<std::uint8_t> hash = nil::crypto3::hash<hashes::blake2b<256>>(transcript_g1s_g1sx);
                        
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
                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_MPC_GENERATOR_HELPERS_HPP
