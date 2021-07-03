//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_R1CS_SE_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_R1CS_SE_PPZKSNARK_BASIC_GENERATOR_HPP

#include <memory>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_se_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A generator algorithm for the R1CS SEppzkSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for
                 * CS.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_generator {
                    typedef detail::r1cs_se_ppzksnark_types_policy<CurveType> policy_type;

                public:
                    typedef CurveType curve_type;

                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline keypair_type process(const constraint_system_type &constraint_system) {

                        /**
                         * draw random element t at which the SAP is evaluated.
                         * it should be the case that Z(t) != 0
                         */
                        const std::shared_ptr<fft::evaluation_domain<typename CurveType::scalar_field_type>> domain =
                            reductions::r1cs_to_sap<typename CurveType::scalar_field_type>::get_domain(
                                constraint_system);
                        typename CurveType::scalar_field_type::value_type t;
                        do {
                            t = algebra::random_element<typename CurveType::scalar_field_type>();
                        } while (domain->compute_vanishing_polynomial(t).is_zero());

                        sap_instance_evaluation<typename CurveType::scalar_field_type> sap_inst =
                            reductions::r1cs_to_sap<
                                typename CurveType::scalar_field_type>::instance_map_with_evaluation(constraint_system,
                                                                                                     t);

                        std::size_t non_zero_At = 0;
                        for (std::size_t i = 0; i < sap_inst.num_variables + 1; ++i) {
                            if (!sap_inst.At[i].is_zero()) {
                                ++non_zero_At;
                            }
                        }

                        std::vector<typename CurveType::scalar_field_type::value_type> At = std::move(sap_inst.At);
                        std::vector<typename CurveType::scalar_field_type::value_type> Ct = std::move(sap_inst.Ct);
                        std::vector<typename CurveType::scalar_field_type::value_type> Ht = std::move(sap_inst.Ht);
                        /**
                         * sap_inst.{A,C,H}t are now in an unspecified state,
                         * but we do not use them below
                         */

                        const typename CurveType::scalar_field_type::value_type
                            alpha = algebra::random_element<typename CurveType::scalar_field_type>(),
                            beta = algebra::random_element<typename CurveType::scalar_field_type>(),
                            gamma = algebra::random_element<typename CurveType::scalar_field_type>();
                        const typename CurveType::g1_type::value_type G =
                            algebra::random_element<typename CurveType::g1_type>();
                        const typename CurveType::g2_type::value_type H =
                            algebra::random_element<typename CurveType::g2_type>();

                        std::size_t G_exp_count = sap_inst.num_inputs + 1    // verifier_query
                                                  + non_zero_At                // A_query
                                                  + sap_inst.degree +
                                                  1    // G_gamma2_Z_t
                                                  // C_query_1
                                                  + sap_inst.num_variables - sap_inst.num_inputs +
                                                  sap_inst.num_variables + 1,    // C_query_2
                            G_window = algebra::get_exp_window_size<typename CurveType::g1_type>(G_exp_count);

                        algebra::window_table<typename CurveType::g1_type> G_table =
                            algebra::get_window_table<typename CurveType::g1_type>(CurveType::scalar_field_type::value_bits, G_window, G);

                        typename CurveType::g2_type::value_type H_gamma = gamma * H;
                        std::size_t H_gamma_exp_count = non_zero_At,    // B_query
                            H_gamma_window =
                                algebra::get_exp_window_size<typename CurveType::g2_type>(H_gamma_exp_count);
                        algebra::window_table<typename CurveType::g2_type> H_gamma_table = algebra::get_window_table<
                            typename CurveType::g2_type>(
                            CurveType::scalar_field_type::value_bits, H_gamma_window, H_gamma);

                        typename CurveType::g1_type::value_type G_alpha = alpha * G;
                        typename CurveType::g2_type::value_type H_beta = beta * H;

                        std::vector<typename CurveType::scalar_field_type::value_type> tmp_exponents;
                        tmp_exponents.reserve(sap_inst.num_inputs + 1);
                        for (std::size_t i = 0; i <= sap_inst.num_inputs; ++i) {
                            tmp_exponents.emplace_back(gamma * Ct[i] + (alpha + beta) * At[i]);
                        }
                        typename std::vector<typename CurveType::g1_type::value_type> verifier_query =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                        tmp_exponents.clear();

                        tmp_exponents.reserve(sap_inst.num_variables + 1);
                        for (std::size_t i = 0; i < At.size(); i++) {
                            tmp_exponents.emplace_back(gamma * At[i]);
                        }

                        typename std::vector<typename CurveType::g1_type::value_type> A_query =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                        tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(A_query);
#endif
                        typename std::vector<typename CurveType::g2_type::value_type> B_query =
                            algebra::batch_exp<typename CurveType::g2_type, typename CurveType::scalar_field_type>(
                                CurveType::scalar_field_type::value_bits, H_gamma_window, H_gamma_table, At);
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g2_type>(B_query);
#endif
                        typename CurveType::g1_type::value_type G_gamma = gamma * G;
                        typename CurveType::g1_type::value_type G_gamma_Z = sap_inst.Zt * G_gamma;
                        typename CurveType::g2_type::value_type H_gamma_Z = sap_inst.Zt * H_gamma;
                        typename CurveType::g1_type::value_type G_ab_gamma_Z = (alpha + beta) * G_gamma_Z;
                        typename CurveType::g1_type::value_type G_gamma2_Z2 = (sap_inst.Zt * gamma) * G_gamma_Z;

                        tmp_exponents.reserve(sap_inst.degree + 1);

                        /* Compute the vector G_gamma2_Z_t := Z(t) * t^i * gamma^2 * G */
                        typename CurveType::scalar_field_type::value_type gamma2_Z_t = sap_inst.Zt * gamma.squared();
                        for (std::size_t i = 0; i < sap_inst.degree + 1; ++i) {
                            tmp_exponents.emplace_back(gamma2_Z_t);
                            gamma2_Z_t *= t;
                        }
                        typename std::vector<typename CurveType::g1_type::value_type> G_gamma2_Z_t =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                        tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(G_gamma2_Z_t);
#endif
                        tmp_exponents.reserve(sap_inst.num_variables - sap_inst.num_inputs);
                        for (std::size_t i = sap_inst.num_inputs + 1; i <= sap_inst.num_variables; ++i) {
                            tmp_exponents.emplace_back(gamma * (gamma * Ct[i] + (alpha + beta) * At[i]));
                        }
                        typename std::vector<typename CurveType::g1_type::value_type> C_query_1 =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                        tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(C_query_1);
#endif

                        tmp_exponents.reserve(sap_inst.num_variables + 1);
                        typename CurveType::scalar_field_type::value_type double_gamma2_Z = gamma * gamma * sap_inst.Zt;
                        double_gamma2_Z = double_gamma2_Z + double_gamma2_Z;
                        for (std::size_t i = 0; i <= sap_inst.num_variables; ++i) {
                            tmp_exponents.emplace_back(double_gamma2_Z * At[i]);
                        }
                        typename std::vector<typename CurveType::g1_type::value_type> C_query_2 =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                        tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(C_query_2);
#endif

                        verification_key_type vk =
                            verification_key_type(H, G_alpha, H_beta, G_gamma, H_gamma, std::move(verifier_query));

                        constraint_system_type cs_copy(constraint_system);

                        proving_key_type pk =
                            proving_key_type(std::move(A_query), std::move(B_query), std::move(C_query_1),
                                             std::move(C_query_2), G_gamma_Z, H_gamma_Z, G_ab_gamma_Z, G_gamma2_Z2,
                                             std::move(G_gamma2_Z_t), std::move(cs_copy));

                        return {std::move(pk), std::move(vk)};
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_SE_PPZKSNARK_BASIC_GENERATOR_HPP
