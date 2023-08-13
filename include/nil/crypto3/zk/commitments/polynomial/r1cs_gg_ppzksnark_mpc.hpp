//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Noam Yemini <noam.yem@gmail.com>
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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_MPC_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_MPC_HPP

#include <nil/crypto3/zk/commitments/detail/polynomial/r1cs_gg_ppzksnark_mpc/private_key.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/r1cs_gg_ppzksnark_mpc/public_key.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/result.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>
#include <nil/crypto3/zk/commitments/polynomial/proof_of_knowledge.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/vector_pairs.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/r1cs_gg_ppzksnark_mpc/crs_operations.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/r1cs_gg_ppzksnark_mpc/public_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/r1cs.hpp>

#include <boost/optional.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_mpc {
                public:
                    typedef CurveType curve_type;
                    typedef snark::r1cs_gg_ppzksnark<curve_type> proving_scheme_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using kc_type = knowledge_commitment<g2_type, g1_type>;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using kc_value_type = typename kc_type::value_type;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using field_value_type = typename scalar_field_type::value_type;

                    typedef detail::r1cs_gg_ppzksnark_mpc_private_key<curve_type> private_key_type;
                    typedef detail::r1cs_gg_ppzksnark_mpc_public_key<curve_type> public_key_type;
                    typedef typename proving_scheme_type::keypair_type proving_scheme_keypair_type;
                    typedef typename proving_scheme_type::constraint_system_type constraint_system_type;
                    typedef proof_of_knowledge<curve_type> proof_of_knowledge_scheme_type;

                    // The result of this function is considered toxic wast
                    // and should thus be destroyed
                    static private_key_type generate_private_key() {
                        typename scalar_field_type::value_type delta = algebra::random_element<scalar_field_type>();
                        return private_key_type{std::move(delta)};
                    }

                    static public_key_type proof_eval(const private_key_type &private_key,
                                                      const boost::optional<public_key_type> &previous_public_key,
                                                      const proving_scheme_keypair_type &mpc_keypair) {
                        std::vector<std::uint8_t> transcript =
                                compute_transcript(mpc_keypair.first.constraint_system, previous_public_key);
                        auto delta_pok = proof_of_knowledge_scheme_type::proof_eval(private_key.delta, transcript, 0);
                        g1_value_type delta_after =
                                private_key.delta *
                                (previous_public_key ? previous_public_key->delta_after : g1_value_type::one());
                        return public_key_type{std::move(delta_after), std::move(delta_pok)};
                    }

                    static bool verify_eval(const proving_scheme_keypair_type &mpc_keypair,
                                            const std::vector<public_key_type> &pubkeys,
                                            const constraint_system_type &constraint_system,
                                            const detail::powers_of_tau_result<curve_type> &powers_of_tau_result) {
                        auto initial_keypair = detail::make_r1cs_gg_ppzksnark_keypair_from_powers_of_tau(
                                constraint_system, powers_of_tau_result);

                        // H/L will change, but should have same length
                        if (initial_keypair.first.H_query.size() != mpc_keypair.first.H_query.size()) {
                            return false;
                        }
                        if (initial_keypair.first.L_query.size() != mpc_keypair.first.L_query.size()) {
                            return false;
                        }

                        // alpha/beta do not change
                        if (initial_keypair.first.alpha_g1 != mpc_keypair.first.alpha_g1) {
                            return false;
                        }
                        if (initial_keypair.first.beta_g1 != mpc_keypair.first.beta_g1) {
                            return false;
                        }
                        if (initial_keypair.first.beta_g2 != mpc_keypair.first.beta_g2) {
                            return false;
                        }

                        // A/B do not change
                        if (initial_keypair.first.A_query != mpc_keypair.first.A_query) {
                            return false;
                        }
                        if (!(initial_keypair.first.B_query == mpc_keypair.first.B_query)) {
                            return false;
                        }

                        // the constraint system doesn't change
                        if (!(initial_keypair.first.constraint_system == mpc_keypair.first.constraint_system)) {
                            return false;
                        }

                        // alpha_beta/gamma do not change
                        if (initial_keypair.second.alpha_g1_beta_g2 != mpc_keypair.second.alpha_g1_beta_g2) {
                            return false;
                        }
                        if (initial_keypair.second.gamma_g2 != mpc_keypair.second.gamma_g2) {
                            return false;
                        }

                        // gamma_ABC_g1 doesn't change
                        if (!(initial_keypair.second.gamma_ABC_g1 == mpc_keypair.second.gamma_ABC_g1)) {
                            return false;
                        }

                        auto transcript = compute_transcript(mpc_keypair.first.constraint_system, boost::none);
                        auto current_delta = g1_value_type::one();
                        for (auto pk: pubkeys) {
                            auto g2_s = proof_of_knowledge_scheme_type::compute_g2_s(
                                    pk.delta_pok.g1_s, pk.delta_pok.g1_s_x, transcript, 0);

                            if (!proof_of_knowledge_scheme_type::verify_eval(pk.delta_pok, g2_s)) {
                                return false;
                            }

                            if (!is_same_ratio(std::make_pair(current_delta, pk.delta_after),
                                               std::make_pair(g2_s, pk.delta_pok.g2_s_x))) {
                                return false;
                            }

                            current_delta = pk.delta_after;
                            transcript = compute_transcript(mpc_keypair.first.constraint_system, pk);
                        }

                        if (current_delta != mpc_keypair.first.delta_g1) {
                            return false;
                        }

                        if (!is_same_ratio(std::make_pair(g1_value_type::one(), current_delta),
                                           std::make_pair(g2_value_type::one(), mpc_keypair.first.delta_g2))) {
                            return false;
                        }

                        if (mpc_keypair.first.delta_g2 != mpc_keypair.second.delta_g2) {
                            return false;
                        }

                        if (!is_same_ratio(
                                detail::merge_pairs<scalar_field_type>(initial_keypair.first.H_query.cbegin(),
                                                                       initial_keypair.first.H_query.cend(),
                                                                       mpc_keypair.first.H_query.cbegin(),
                                                                       mpc_keypair.first.H_query.cend()),
                                std::make_pair(mpc_keypair.first.delta_g2, g2_value_type::one()))) {
                            return false;
                        }

                        if (!is_same_ratio(
                                detail::merge_pairs<scalar_field_type>(initial_keypair.first.L_query.cbegin(),
                                                                       initial_keypair.first.L_query.cend(),
                                                                       mpc_keypair.first.L_query.cbegin(),
                                                                       mpc_keypair.first.L_query.cend()),
                                std::make_pair(mpc_keypair.first.delta_g2, g2_value_type::one()))) {
                            return false;
                        }

                        return true;
                    }

                    static bool is_same_ratio(const std::pair<g1_value_type, g1_value_type> &g1_pair,
                                              const std::pair<g2_value_type, g2_value_type> &g2_pair) {

                        return algebra::pair_reduced<CurveType>(g1_pair.first, g2_pair.second) ==
                               algebra::pair_reduced<CurveType>(g1_pair.second, g2_pair.first);
                    }

                    static std::vector<std::uint8_t>
                    compute_transcript(const constraint_system_type &constraint_system,
                                       const boost::optional<public_key_type> &pubkey) {
                        std::vector<uint8_t> cs_blob = serialize_constraint_system(constraint_system);
                        std::vector<std::uint8_t> cs_pk_blob;
                        std::copy(std::cbegin(cs_blob), std::cend(cs_blob), std::back_inserter(cs_pk_blob));
                        if (pubkey) {
                            std::vector<uint8_t> pk_blob = serialize_public_key(*pubkey);
                            std::copy(std::cbegin(pk_blob), std::cend(pk_blob), std::back_inserter(cs_pk_blob));
                        }
                        return nil::crypto3::hash<hashes::blake2b<512>>(cs_pk_blob);
                    }

                    static std::vector<std::uint8_t> serialize_public_key(const public_key_type &pubkey) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val =
                                nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_mpc_public_key<public_key_type,
                                        endianness>(pubkey);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        if (status != nil::marshalling::status_type::success) {
                            return {};
                        } else {
                            return blob;
                        }
                    }

                    static std::vector<std::uint8_t>
                    serialize_constraint_system(const constraint_system_type &constraint_system) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val =
                                nil::crypto3::marshalling::types::fill_r1cs_constraint_system<constraint_system_type,
                                        endianness>(
                                        constraint_system);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        if (status != nil::marshalling::status_type::success) {
                            return {};
                        } else {
                            return blob;
                        }
                    }
                };
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_MPC_HPP