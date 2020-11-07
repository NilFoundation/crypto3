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
// @file Declaration of interfaces for a ppzkSNARK for R1CS.
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
// The implementation instantiates (a modification of) the protocol of \[PGHR13],
// by following extending, and optimizing the approach described in \[BCTV14].
//
//
// Acronyms:
//
// - R1CS = "Rank-1 Constraint Systems"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//
// \[PGHR13]:
// "Pinocchio: Nearly practical verifiable computation",
// Bryan Parno, Craig Gentry, Jon Howell, Mariana Raykova,
// IEEE S&P 2013,
// <https://eprint.iacr.org/2013/279>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_R1CS_PPZKSNARK_BASIC_GENERATOR_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

//#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    using types_policy = detail::r1cs_ppzksnark_types_policy;

                    using constraint_system_type = typename policy_type::constraint_system;
                    using primary_input_type = typename policy_type::primary_input;
                    using auxiliary_input_type = typename policy_type::auxiliary_input;

                    using proving_key_type = typename policy_type::proving_key;
                    using verification_key_type = typename policy_type::verification_key;
                    using processed_verification_key_type = typename policy_type::processed_verification_key;

                    using keypair_type = typename policy_type::keypair;
                    using proof_type = typename policy_type::proof;

                    struct r1cs_ppzksnark_generator {

                        template<typename CurveType>
                        keypair_type operator()(const constraint_system_type &constraint_system) {

                            /* make the B_query "lighter" if possible */
                            constraint_system_type cs_copy(constraint_system);
                            cs_copy.swap_AB_if_beneficial();

                            /* draw random element at which the QAP is evaluated */
                            const typename CurveType::scalar_field_type::value_type t =
                                algebra::random_element<typename CurveType::scalar_field_type>();

                            qap_instance_evaluation<typename CurveType::scalar_field_type> qap_inst =
                                r1cs_to_qap::instance_map_with_evaluation(cs_copy, t);

                            std::size_t non_zero_At = 0, non_zero_Bt = 0, non_zero_Ct = 0, non_zero_Ht = 0;
                            for (std::size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                                if (!qap_inst.At[i].is_zero()) {
                                    ++non_zero_At;
                                }
                                if (!qap_inst.Bt[i].is_zero()) {
                                    ++non_zero_Bt;
                                }
                                if (!qap_inst.Ct[i].is_zero()) {
                                    ++non_zero_Ct;
                                }
                            }
                            for (std::size_t i = 0; i < qap_inst.degree() + 1; ++i) {
                                if (!qap_inst.Ht[i].is_zero()) {
                                    ++non_zero_Ht;
                                }
                            }

                            std::vector<typename CurveType::scalar_field_type::value_type> At = std::move(
                                qap_inst.At);    // qap_inst.At is now in unspecified state, but we do not use it later
                            std::vector<typename CurveType::scalar_field_type::value_type> Bt = std::move(
                                qap_inst.Bt);    // qap_inst.Bt is now in unspecified state, but we do not use it later
                            std::vector<typename CurveType::scalar_field_type::value_type> Ct = std::move(
                                qap_inst.Ct);    // qap_inst.Ct is now in unspecified state, but we do not use it later
                            std::vector<typename CurveType::scalar_field_type::value_type> Ht = std::move(
                                qap_inst.Ht);    // qap_inst.Ht is now in unspecified state, but we do not use it later

                            /* append Zt to At,Bt,Ct with */
                            At.emplace_back(qap_inst.Zt);
                            Bt.emplace_back(qap_inst.Zt);
                            Ct.emplace_back(qap_inst.Zt);

                            const typename CurveType::scalar_field_type::value_type
                                alphaA = algebra::random_element<typename CurveType::scalar_field_type>(),
                                alphaB = algebra::random_element<typename CurveType::scalar_field_type>(),
                                alphaC = algebra::random_element<typename CurveType::scalar_field_type>(),
                                rA = algebra::random_element<typename CurveType::scalar_field_type>(),
                                rB = algebra::random_element<typename CurveType::scalar_field_type>(),
                                beta = algebra::random_element<typename CurveType::scalar_field_type>(),
                                gamma = algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type rC = rA * rB;

                            // consrtuct the same-coefficient-check query (must happen before zeroing out the prefix of
                            // At)
                            std::vector<typename CurveType::scalar_field_type::value_type> Kt;
                            Kt.reserve(qap_inst.num_variables() + 4);
                            for (std::size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                                Kt.emplace_back(beta * (rA * At[i] + rB * Bt[i] + rC * Ct[i]));
                            }
                            Kt.emplace_back(beta * rA * qap_inst.Zt);
                            Kt.emplace_back(beta * rB * qap_inst.Zt);
                            Kt.emplace_back(beta * rC * qap_inst.Zt);

                            /* zero out prefix of At and stick it into IC coefficients */
                            std::vector<typename CurveType::scalar_field_type::value_type> IC_coefficients;
                            IC_coefficients.reserve(qap_inst.num_inputs() + 1);
                            for (std::size_t i = 0; i < qap_inst.num_inputs() + 1; ++i) {
                                IC_coefficients.emplace_back(At[i]);
                                assert(!IC_coefficients[i].is_zero());
                                At[i] = typename CurveType::scalar_field_type::zero();
                            }

                            const std::size_t g1_exp_count = 2 * (non_zero_At - qap_inst.num_inputs() + non_zero_Ct) +
                                                             non_zero_Bt + non_zero_Ht + Kt.size();
                            const std::size_t g2_exp_count = non_zero_Bt;

                            std::size_t g1_window =
                                algebra::get_exp_window_size<typename CurveType::g1_type>(g1_exp_count);
                            std::size_t g2_window =
                                algebra::get_exp_window_size<typename CurveType::g2_type>(g2_exp_count);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            algebra::window_table<typename CurveType::g1_type> g1_table =
                                get_window_table(typename CurveType::scalar_field_type::value_bits, g1_window,
                                                 typename CurveType::g1_type::value_type::one());

                            algebra::window_table<typename CurveType::g2_type> g2_table =
                                get_window_table(typename CurveType::scalar_field_type::value_bits, g2_window,
                                                 typename CurveType::g2_type::value_type::one());

                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                A_query = kc_batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window,
                                                       g1_window, g1_table, g1_table, rA, rA * alphaA, At, chunks);

                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                                B_query = kc_batch_exp(typename CurveType::scalar_field_type::value_bits, g2_window,
                                                       g1_window, g2_table, g1_table, rB, rB * alphaB, Bt, chunks);

                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                C_query = kc_batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window,
                                                       g1_window, g1_table, g1_table, rC, rC * alphaC, Ct, chunks);

                            typename std::vector<typename CurveType::g1_type::value_type> H_query =
                                batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(H_query);
#endif

                            typename std::vector<typename CurveType::g1_type::value_type> K_query =
                                batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window, g1_table, Kt);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(K_query);
#endif

                            typename CurveType::g2_type::value_type alphaA_g2 =
                                alphaA * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g1_type::value_type alphaB_g1 =
                                alphaB * typename CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type alphaC_g2 =
                                alphaC * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g2_type::value_type gamma_g2 =
                                gamma * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g1_type::value_type gamma_beta_g1 =
                                (gamma * beta) * typename CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type gamma_beta_g2 =
                                (gamma * beta) * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g2_type::value_type rC_Z_g2 =
                                (rC * qap_inst.Zt) * typename CurveType::g2_type::value_type::one();

                            typename CurveType::g1_type::value_type encoded_IC_base =
                                (rA * IC_coefficients[0]) * typename CurveType::g1_type::value_type::one();
                            std::vector<typename CurveType::scalar_field_type::value_type> multiplied_IC_coefficients;
                            multiplied_IC_coefficients.reserve(qap_inst.num_inputs());
                            for (std::size_t i = 1; i < qap_inst.num_inputs() + 1; ++i) {
                                multiplied_IC_coefficients.emplace_back(rA * IC_coefficients[i]);
                            }
                            typename std::vector<typename CurveType::g1_type::value_type> encoded_IC_values =
                                batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window, g1_table,
                                          multiplied_IC_coefficients);

                            accumulation_vector<typename CurveType::g1_type> encoded_IC_query(
                                std::move(encoded_IC_base), std::move(encoded_IC_values));

                            verification_key vk =
                                verification_key(alphaA_g2, alphaB_g1, alphaC_g2, gamma_g2, gamma_beta_g1,
                                                 gamma_beta_g2, rC_Z_g2, encoded_IC_query);
                            proving_key pk = proving_key(std::move(A_query),
                                                         std::move(B_query),
                                                         std::move(C_query),
                                                         std::move(H_query),
                                                         std::move(K_query),
                                                         std::move(cs_copy));

                            pk.print_size();
                            vk.print_size();

                            return keypair(std::move(pk), std::move(vk));
                        }
                    };
                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_GENERATOR_HPP
