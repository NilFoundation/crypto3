//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for a ppzkSNARK for BACS.
//
// This includes:
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key pair (proving key & verification key)
// - class for proof
// - generator algorithm
// - prover algorithm
// - verifier algorithm (with strong or weak input consistency)
// - online verifier algorithm (with strong or weak input consistency)
//
// The implementation is a straightforward combination of:
// (1) a BACS-to-R1CS reduction, and
// (2) a ppzkSNARK for R1CS.
//
//
// Acronyms:
//
// - BACS = "Bilinear Arithmetic Circuit Satisfiability"
// - R1CS = "Rank-1 Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_GENERATOR_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

//#include <nil/crypto3/algebra/multiexp/default.hpp>

//#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

//#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /**
                     * A generator algorithm for the R1CS GG-ppzkSNARK.
                     *
                     * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for
                     * CS.
                     */
                    template<typename CurveType>
                    class r1cs_gg_ppzksnark_generator {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy<CurveType>;

                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline keypair_type process(const constraint_system_type &cs) {

                            typedef typename CurveType::pairing_policy pairing_policy;

                            /* Make the B_query "lighter" if possible */
                            constraint_system_type r1cs_copy(cs);
                            r1cs_copy.swap_AB_if_beneficial();

                            /* Generate secret randomness */
                            const typename CurveType::scalar_field_type::value_type t =
                                algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type alpha =
                                algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type beta =
                                algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type gamma =
                                algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type delta =
                                algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type gamma_inverse = gamma.inversed();
                            const typename CurveType::scalar_field_type::value_type delta_inverse = delta.inversed();

                            /* A quadratic arithmetic program evaluated at t. */
                            qap_instance_evaluation<typename CurveType::scalar_field_type> qap =
                                r1cs_to_qap<CurveType>::instance_map_with_evaluation(r1cs_copy, t);

                            std::size_t non_zero_At = 0;
                            std::size_t non_zero_Bt = 0;
                            for (std::size_t i = 0; i < qap.num_variables + 1; ++i) {
                                if (!qap.At[i].is_zero()) {
                                    ++non_zero_At;
                                }
                                if (!qap.Bt[i].is_zero()) {
                                    ++non_zero_Bt;
                                }
                            }

                            /* qap.{At,Bt,Ct,Ht} are now in unspecified state, but we do not use them later */
                            std::vector<typename CurveType::scalar_field_type::value_type> At = std::move(qap.At);
                            std::vector<typename CurveType::scalar_field_type::value_type> Bt = std::move(qap.Bt);
                            std::vector<typename CurveType::scalar_field_type::value_type> Ct = std::move(qap.Ct);
                            std::vector<typename CurveType::scalar_field_type::value_type> Ht = std::move(qap.Ht);

                            /* The gamma inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * gamma^{-1}.
                             */
                            std::vector<typename CurveType::scalar_field_type::value_type> gamma_ABC;
                            gamma_ABC.reserve(qap.num_inputs);

                            const typename CurveType::scalar_field_type::value_type gamma_ABC_0 =
                                (beta * At[0] + alpha * Bt[0] + Ct[0]) * gamma_inverse;
                            for (std::size_t i = 1; i < qap.num_inputs + 1; ++i) {
                                gamma_ABC.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
                            }

                            /* The delta inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}.
                             */
                            std::vector<typename CurveType::scalar_field_type::value_type> Lt;
                            Lt.reserve(qap.num_variables - qap.num_inputs);

                            const std::size_t Lt_offset = qap.num_inputs + 1;
                            for (std::size_t i = 0; i < qap.num_variables - qap.num_inputs; ++i) {
                                Lt.emplace_back(
                                    (beta * At[Lt_offset + i] + alpha * Bt[Lt_offset + i] + Ct[Lt_offset + i]) *
                                    delta_inverse);
                            }

                            /**
                             * Note that H for Groth's proof system is degree d-2, but the QAP
                             * reduction returns coefficients for degree d polynomial H (in
                             * style of PGHR-type proof systems)
                             */
                            Ht.resize(Ht.size() - 2);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            const typename CurveType::g1_type::value_type g1_generator =
                                algebra::random_element<typename CurveType::g1_type>();
                            const std::size_t g1_scalar_count = non_zero_At + non_zero_Bt + qap.num_variables;
                            const std::size_t g1_scalar_size = CurveType::scalar_field_type::value_bits;
                            const std::size_t g1_window_size = 128;
                            // algebra::get_exp_window_size<typename CurveType::g1_type>(g1_scalar_count);
                            // uncomment
                            // when get_exp_window_size ready

                            std::vector<std::vector<typename CurveType::g1_type::value_type>> g1_table;
                            /*algebra::window_table<typename CurveType::g1_type> g1_table =
                                algebra::get_window_table(g1_scalar_size, g1_window_size, g1_generator);*/
                            // uncomment
                            // when get_window_table ready

                            const typename CurveType::g2_type::value_type G2_gen =
                                algebra::random_element<typename CurveType::g2_type>();
                            const std::size_t g2_scalar_count = non_zero_Bt;
                            const std::size_t g2_scalar_size = CurveType::scalar_field_type::value_bits;
                            std::size_t g2_window_size = 128;
                            // algebra::get_exp_window_size<typename CurveType::g2_type>(g2_scalar_count);
                            // uncomment
                            // when get_exp_window_size ready

                            std::vector<std::vector<typename CurveType::g2_type>> g2_table;
                            /*algebra::window_table<typename CurveType::g2_type> g2_table =
                                algebra::get_window_table(g2_scalar_size, g2_window_size, G2_gen);*/
                            // uncomment
                            // when get_window_table ready

                            typename CurveType::g1_type::value_type alpha_g1 = g1_generator;
                            typename CurveType::g1_type::value_type beta_g1 = g1_generator;
                            typename CurveType::g2_type::value_type beta_g2 = G2_gen;
                            typename CurveType::g1_type::value_type delta_g1 = g1_generator;
                            typename CurveType::g2_type::value_type delta_g2 = G2_gen;

                            /*typename CurveType::g1_type::value_type alpha_g1 = alpha * g1_generator;
                            typename CurveType::g1_type::value_type beta_g1 = beta * g1_generator;
                            typename CurveType::g2_type::value_type beta_g2 = beta * G2_gen;
                            typename CurveType::g1_type::value_type delta_g1 = delta * g1_generator;
                            typename CurveType::g2_type::value_type delta_g2 = delta * G2_gen;*/
                            // uncomment
                            // when multiplication ready

                            typename std::vector<typename CurveType::g1_type::value_type> A_query;
                            //= batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
                            // uncomment
                            // when batch_exp ready
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(A_query);
#endif

                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                                B_query /*=
                                kc_batch_exp(CurveType::scalar_field_type::value_bits, g2_window_size, g1_window_size,
                                g2_table, g1_table, CurveType::scalar_field_type::value_type::one(),
                                CurveType::scalar_field_type::value_type::one(), Bt, chunks)*/
                                ;

                            // uncomment
                            // when multiexp ready

                            // NOTE: if USE_MIXED_ADDITION is defined,
                            // kc_batch_exp will convert its output to special form internally

                            typename std::vector<typename CurveType::g1_type::value_type> H_query;
                            //= batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse,
                            // Ht);
                            // uncomment
                            // when batch_exp_with_coeff ready
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(H_query);
#endif

                            typename std::vector<typename CurveType::g1_type::value_type> L_query;
                            //= batch_exp(g1_scalar_size, g1_window_size, g1_table, Lt);
                            // uncomment
                            // when batch_exp ready
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(L_query);
#endif

                            typename CurveType::gt_type alpha_g1_beta_g2 =
                                pairing_policy::reduced_pairing(alpha_g1, beta_g2);
                            typename CurveType::g2_type::value_type gamma_g2 = G2_gen;
                            // typename CurveType::g2_type::value_type gamma_g2 = gamma * G2_gen;
                            // uncomment
                            // when multiplication ready

                            typename CurveType::g1_type::value_type gamma_ABC_g1_0 = g1_generator;
                            // typename CurveType::g1_type::value_type gamma_ABC_g1_0 = gamma_ABC_0 * g1_generator;
                            // uncomment
                            // when multiplication ready
                            typename std::vector<typename CurveType::g1_type::value_type> gamma_ABC_g1_values;
                            //= batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_ABC);
                            // uncomment
                            // when batch_exp ready

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1(
                                std::move(gamma_ABC_g1_0), std::move(gamma_ABC_g1_values));

                            verification_key_type vk =
                                verification_key(alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);

                            proving_key_type pk = proving_key(std::move(alpha_g1),
                                                              std::move(beta_g1),
                                                              std::move(beta_g2),
                                                              std::move(delta_g1),
                                                              std::move(delta_g2),
                                                              std::move(A_query),
                                                              std::move(B_query),
                                                              std::move(H_query),
                                                              std::move(L_query),
                                                              std::move(r1cs_copy));

                            return keypair_type(std::move(pk), std::move(vk));
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_GENERATOR_HPP
