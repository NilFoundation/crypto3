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

#ifndef CRYPTO3_R1CS_MPC_GENERATOR_HPP
#define CRYPTO3_R1CS_MPC_GENERATOR_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/private_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/public_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/mpc_params.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/helpers.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <vector>
#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_mpc_generator {
                    typedef CurveType curve_type;
                    typedef r1cs_gg_ppzksnark<curve_type> proving_scheme_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_private_key<curve_type> private_key_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_public_key<curve_type> public_key_type;
                    typedef r1cs_gg_ppzksnark_mpc_params<curve_type> mpc_params_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_helpers<curve_type> helpers_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using kc_type = commitments::knowledge_commitment<g2_type, g1_type>;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using kc_value_type = typename kc_type::value_type;
                    using scalar_field_type = typename curve_type::scalar_field_type; 
                    using field_value_type = typename scalar_field_type::value_type; 

                public:
                    static mpc_params_type
                        init_mpc_keypair(const typename proving_scheme_type::constraint_system_type &constraint_system,
                                         const powers_of_tau_result<curve_type> &powers_of_tau_result) {
                        g1_value_type alpha_g1 = powers_of_tau_result.alpha_g1;
                        g1_value_type beta_g1 = powers_of_tau_result.beta_g1;
                        g2_value_type beta_g2 = powers_of_tau_result.beta_g2;

                        std::vector<g1_value_type> coeffs_g1 = powers_of_tau_result.coeffs_g1;
                        std::vector<g2_value_type> coeffs_g2 = powers_of_tau_result.coeffs_g2;
                        std::vector<g1_value_type> alpha_coeffs_g1 = powers_of_tau_result.alpha_coeffs_g1;
                        std::vector<g1_value_type> beta_coeffs_g1 = powers_of_tau_result.beta_coeffs_g1;

                        typename proving_scheme_type::constraint_system_type r1cs_copy(constraint_system);
                        r1cs_copy.swap_AB_if_beneficial();

                        qap_instance<scalar_field_type> qap = reductions::r1cs_to_qap<scalar_field_type, reductions::domain_mode::basic_only>::instance_map(r1cs_copy);

                        std::vector<g1_value_type> beta_a_alpha_b_c(qap.num_variables + 1, g1_value_type::zero());
                        std::vector<g1_value_type> a_g1(qap.num_variables + 1, g1_value_type::zero());
                        std::vector<kc_value_type> b_kc(qap.num_variables + 1, kc_value_type::zero());

                        for(std::size_t i = 0; i < qap.num_variables + 1; ++i) {
                            for(auto [lag, coeff] : qap.A_in_Lagrange_basis[i]){
                                a_g1[i] = a_g1[i] + coeff * coeffs_g1[lag];
                                beta_a_alpha_b_c[i] = beta_a_alpha_b_c[i] + coeff * beta_coeffs_g1[lag];
                            }
                            for(auto [lag, coeff] : qap.B_in_Lagrange_basis[i]){
                                b_kc[i] = b_kc[i] + coeff * kc_value_type(coeffs_g2[lag], coeffs_g1[lag]);
                                beta_a_alpha_b_c[i] = beta_a_alpha_b_c[i] + coeff * alpha_coeffs_g1[lag];
                            }
                            for(auto [lag, coeff] : qap.C_in_Lagrange_basis[i]){
                                beta_a_alpha_b_c[i] = beta_a_alpha_b_c[i] + coeff * coeffs_g1[lag];
                            }
                        }

                        auto alpha_g1_beta_g2 = algebra::pair_reduced<curve_type>(alpha_g1, beta_g2);
                        auto gamma_g2 = g2_value_type::one();
                        auto delta_g1 = g1_value_type::one();
                        auto delta_g2 = g2_value_type::one();
                        auto gamma_ABC_g1_0 = beta_a_alpha_b_c[0];
                        std::vector<g1_value_type> gamma_ABC_g1_values(beta_a_alpha_b_c.begin() + 1, beta_a_alpha_b_c.begin() + 1 + qap.num_inputs);
                        container::accumulation_vector<g1_type> gamma_ABC(
                            std::move(gamma_ABC_g1_0), std::move(gamma_ABC_g1_values)
                        );
                        typename proving_scheme_type::verification_key_type vk(
                            alpha_g1_beta_g2,
                            gamma_g2,
                            delta_g2,
                            gamma_ABC
                        );

                        commitments::knowledge_commitment_vector<g2_type,g1_type> B_query(std::move(b_kc));
                        std::vector<g1_value_type> H_query(powers_of_tau_result.h.begin(), powers_of_tau_result.h.begin() + qap.degree - 1);
                        std::size_t Lt_offset = qap.num_inputs + 1;
                        std::vector<g1_value_type> L_query(beta_a_alpha_b_c.begin() + Lt_offset, beta_a_alpha_b_c.end());
                        typename proving_scheme_type::proving_key_type pk(
                            alpha_g1,
                            beta_g1,
                            beta_g2,
                            delta_g1,
                            delta_g2,
                            a_g1,
                            B_query,
                            H_query,
                            L_query,
                            r1cs_copy
                        );

                        typename proving_scheme_type::keypair_type keypair {std::move(pk), std::move(vk)};

                        return mpc_params_type {
                            keypair
                        };
                    }

                    static public_key_type contribute_first_randomness(mpc_params_type &mpc_params) {
                        auto transcript = helpers_type::compute_transcript(mpc_params.keypair.first.constraint_system);
                        auto [pk, sk] = helpers_type::generate_keypair(mpc_params.keypair.first.delta_g1, transcript);
                        
                        auto delta_inv = sk.delta.inversed();
                        for(auto& g :  mpc_params.keypair.first.H_query) {
                            g = g*delta_inv;
                        }

                        for(auto& g :  mpc_params.keypair.first.L_query) {
                            g = g*delta_inv;
                        }

                        mpc_params.keypair.first.delta_g1 = sk.delta * mpc_params.keypair.first.delta_g1;
                        mpc_params.keypair.first.delta_g2 = sk.delta * mpc_params.keypair.first.delta_g2;
                        mpc_params.keypair.second.delta_g2 = sk.delta * mpc_params.keypair.second.delta_g2;

                        return pk;
                    }

                    static public_key_type contribute_randomness(mpc_params_type &mpc_params, const public_key_type &previous_pubkey) {
                        auto transcript = helpers_type::compute_transcript(mpc_params.keypair.first.constraint_system, previous_pubkey);
                        auto [pk, sk] = helpers_type::generate_keypair(mpc_params.keypair.first.delta_g1, transcript);
                        
                        auto delta_inv = sk.delta.inversed();
                        for(auto& g :  mpc_params.keypair.first.H_query) {
                            g = g*delta_inv;
                        }

                        for(auto& g :  mpc_params.keypair.first.L_query) {
                            g = g*delta_inv;
                        }

                        mpc_params.keypair.first.delta_g1 = sk.delta * mpc_params.keypair.first.delta_g1;
                        mpc_params.keypair.first.delta_g2 = sk.delta * mpc_params.keypair.first.delta_g2;
                        mpc_params.keypair.second.delta_g2 = sk.delta * mpc_params.keypair.second.delta_g2;

                        return pk;
                    }

                    static bool verify(const mpc_params_type &mpc_params, const std::vector<public_key_type> &pubkeys,
                                       const typename proving_scheme_type::constraint_system_type &constraint_system,
                                       const powers_of_tau_result<curve_type> &powers_of_tau_result) {
                        auto initial_params = init_mpc_keypair(constraint_system, powers_of_tau_result);

                        // H/L will change, but should have same length
                        if(initial_params.keypair.first.H_query.size() != mpc_params.keypair.first.H_query.size()) {
                            return false;
                        }
                        if(initial_params.keypair.first.L_query.size() != mpc_params.keypair.first.L_query.size()) {
                            return false;
                        }

                        // alpha/beta do not change
                        if(initial_params.keypair.first.alpha_g1 != mpc_params.keypair.first.alpha_g1) {
                            return false;
                        }
                        if(initial_params.keypair.first.beta_g1 != mpc_params.keypair.first.beta_g1) {
                            return false;
                        }
                        if(initial_params.keypair.first.beta_g2 != mpc_params.keypair.first.beta_g2) {
                            return false;
                        }

                        // A/B do not change
                        if(initial_params.keypair.first.A_query != mpc_params.keypair.first.A_query) {
                            return false;
                        }
                        if(!(initial_params.keypair.first.B_query == mpc_params.keypair.first.B_query)) {
                            return false;
                        }
                        
                        // the constraint system doesn't change
                        if(!(initial_params.keypair.first.constraint_system == mpc_params.keypair.first.constraint_system)) {
                            return false;
                        }
                        
                        // alpha_beta/gamma do not change
                        if(initial_params.keypair.second.alpha_g1_beta_g2 != mpc_params.keypair.second.alpha_g1_beta_g2) {
                            return false;
                        }
                        if(initial_params.keypair.second.gamma_g2 != mpc_params.keypair.second.gamma_g2) {
                            return false;
                        }

                        // gamma_ABC_g1 doesn't change
                        if(!(initial_params.keypair.second.gamma_ABC_g1 == mpc_params.keypair.second.gamma_ABC_g1)) {
                            return false;
                        }
                        
                        auto transcript = helpers_type::compute_transcript(mpc_params.keypair.first.constraint_system);
                        auto current_delta = g1_value_type::one();
                        for(auto pk : pubkeys) {
                            auto g2_s = helpers_type::compute_g2_s(pk.delta_pok.g1_s, pk.delta_pok.g1_s_x, transcript);
                            
                            if (!helpers_type::verify_pok(pk.delta_pok, g2_s)) {
                                return false;
                            }

                            if (!helpers_type::is_same_ratio(std::make_pair(current_delta, pk.delta_after),
                                                             std::make_pair(g2_s, pk.delta_pok.g2_s_x))) {
                                return false;
                            }
                            
                            current_delta = pk.delta_after;
                            transcript = helpers_type::compute_transcript(mpc_params.keypair.first.constraint_system, pk);
                        }

                        if(current_delta != mpc_params.keypair.first.delta_g1) {
                            return false;
                        }
                        
                        if(!helpers_type::is_same_ratio(std::make_pair(g1_value_type::one(), current_delta),
                                                        std::make_pair(g2_value_type::one(), mpc_params.keypair.first.delta_g2))) {
                            return false;
                        }

                        if(mpc_params.keypair.first.delta_g2 != mpc_params.keypair.second.delta_g2) {
                            return false;
                        }

                        if(!helpers_type::is_same_ratio(
                                helpers_type::merge_pairs(initial_params.keypair.first.H_query.cbegin(),
                                    initial_params.keypair.first.H_query.cend(),
                                    mpc_params.keypair.first.H_query.cbegin(),
                                    mpc_params.keypair.first.H_query.cend()),
                                std::make_pair(mpc_params.keypair.first.delta_g2, g2_value_type::one())
                            )) {
                            return false;
                        }

                        if(!helpers_type::is_same_ratio(
                                helpers_type::merge_pairs(initial_params.keypair.first.L_query.cbegin(),
                                    initial_params.keypair.first.L_query.cend(),
                                    mpc_params.keypair.first.L_query.cbegin(),
                                    mpc_params.keypair.first.L_query.cend()),
                                std::make_pair(mpc_params.keypair.first.delta_g2, g2_value_type::one())
                            )) {
                            return false;
                        }

                        return true;
                    }

               private:
                    template<typename PointIterator, typename ScalarIterator>
                    void naive_batch_exp(const PointIterator &bases_begin,
                                        const PointIterator &bases_end,
                                        const ScalarIterator &pow_begin,
                                        const ScalarIterator &pow_end) {
                        BOOST_ASSERT(std::distance(bases_begin, bases_end) <= std::distance(pow_begin, pow_end));
                        
                        auto base_iter = bases_begin;
                        auto pow_iter = pow_begin;
                        while(base_iter < bases_end) {
                            *base_iter = *pow_iter * *base_iter;
                            ++base_iter;
                            ++pow_iter;
                        }
                    }

                    template<typename PointIterator, typename ScalarIterator>
                    void naive_batch_exp_with_coeff(const PointIterator &bases_begin,
                                        const PointIterator &bases_end,
                                        const ScalarIterator &pow_begin,
                                        const ScalarIterator &pow_end,
                                        const field_value_type & coeff) {
                        BOOST_ASSERT(std::distance(bases_begin, bases_end) <= std::distance(pow_begin, pow_end));
                        
                        auto base_iter = bases_begin;
                        auto pow_iter = pow_begin;
                        while(base_iter < bases_end) {
                            *base_iter = (coeff * *pow_iter) * *base_iter;
                            ++base_iter;
                            ++pow_iter;
                        }
                    }
                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_MPC_GENERATOR_HPP
