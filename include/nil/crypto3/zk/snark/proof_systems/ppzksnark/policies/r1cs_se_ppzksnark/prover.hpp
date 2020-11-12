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

#ifndef CRYPTO3_ZK_R1CS_SE_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_ZK_R1CS_SE_PPZKSNARK_BASIC_PROVER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_se_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /**
                     * A prover algorithm for the R1CS SEppzkSNARK.
                     *
                     * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                     * produces a proof (of knowledge) that attests to the following statement:
                     *               ``there exists Y such that CS(X,Y)=0''.
                     * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                     */
                    template<typename CurveType>
                    class r1cs_se_ppzksnark_prover {
                        using types_policy = detail::r1cs_se_ppzksnark_types_policy<CurveType>;

                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline proof_type process(const proving_key_type &proving_key,
                                                         const primary_input_type &primary_input,
                                                         const auxiliary_input_type &auxiliary_input) {

                            const typename CurveType::scalar_field_type::value_type
                                d1 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                d2 = algebra::random_element<typename CurveType::scalar_field_type>();

                            const sap_witness<typename CurveType::scalar_field_type> sap_wit =
                                r1cs_to_sap<CurveType>::witness_map(
                                    proving_key.constraint_system, primary_input, auxiliary_input, d1, d2);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            const typename CurveType::scalar_field_type::value_type r =
                                algebra::random_element<typename CurveType::scalar_field_type>();

                            /**
                             * compute A = G^{gamma * (\sum_{i=0}^m input_i * A_i(t) + r * Z(t))}
                             *           = \prod_{i=0}^m (G^{gamma * A_i(t)})^{input_i)
                             *             * (G^{gamma * Z(t)})^r
                             *           = \prod_{i=0}^m A_query[i]^{input_i} * G_gamma_Z^r
                             */
                            typename CurveType::g1_type::value_type A =
                                r * proving_key.G_gamma_Z +
                                proving_key.A_query[0] +                // i = 0 is a special case because input_i = 1
                                sap_wit.d1 * proving_key.G_gamma_Z +    // ZK-patch
                                algebra::multiexp<typename CurveType::g1_type,
                                                  typename CurveType::scalar_field_type,
                                                  algebra::policies::multiexp_method_BDLO12<
                                                  typename CurveType::g1_type,
                                                  typename CurveType::scalar_field_type>>
                                                  (proving_key.A_query.begin() + 1,
                                                                                   proving_key.A_query.end(),
                                                                                   sap_wit.coefficients_for_ACs.begin(),
                                                                                   sap_wit.coefficients_for_ACs.end(),
                                                                                   chunks);

                            /**
                             * compute B exactly as A, except with H as the base
                             */
                            typename CurveType::g2_type::value_type B =
                                r * proving_key.H_gamma_Z +
                                proving_key.B_query[0] +                // i = 0 is a special case because input_i = 1
                                sap_wit.d1 * proving_key.H_gamma_Z +    // ZK-patch
                                algebra::multiexp<typename CurveType::g2_type,
                                                  typename CurveType::scalar_field_type,
                                                  algebra::policies::multiexp_method_BDLO12<
                                                  typename CurveType::g2_type,
                                                  typename CurveType::scalar_field_type>>
                                                  (proving_key.B_query.begin() + 1,
                                                                                   proving_key.B_query.end(),
                                                                                   sap_wit.coefficients_for_ACs.begin(),
                                                                                   sap_wit.coefficients_for_ACs.end(),
                                                                                   chunks);
                            /**
                             * compute C = G^{f(input) +
                             *                r^2 * gamma^2 * Z(t)^2 +
                             *                r * (alpha + beta) * gamma * Z(t) +
                             *                2 * r * gamma^2 * Z(t) * \sum_{i=0}^m input_i A_i(t) +
                             *                gamma^2 * Z(t) * H(t)}
                             * where G^{f(input)} = \prod_{i=l+1}^m C_query_1 * input_i
                             * and G^{2 * r * gamma^2 * Z(t) * \sum_{i=0}^m input_i A_i(t)} =
                             *              = \prod_{i=0}^m C_query_2 * input_i
                             */
                            typename CurveType::g1_type::value_type C =
                                algebra::multiexp<typename CurveType::g1_type,
                                                  typename CurveType::scalar_field_type,
                                                  algebra::policies::multiexp_method_BDLO12<
                                                  typename CurveType::g1_type,
                                                  typename CurveType::scalar_field_type>>(
                                    proving_key.C_query_1.begin(),
                                    proving_key.C_query_1.end(),
                                    sap_wit.coefficients_for_ACs.begin() + sap_wit.num_inputs(),
                                    sap_wit.coefficients_for_ACs.end(),
                                    chunks) +
                                (r * r) * proving_key.G_gamma2_Z2 + r * proving_key.G_ab_gamma_Z +
                                sap_wit.d1 * proving_key.G_ab_gamma_Z +    // ZK-patch
                                r * proving_key.C_query_2[0] +             // i = 0 is a special case for C_query_2
                                (r + r) * sap_wit.d1 * proving_key.G_gamma2_Z2 +    // ZK-patch for C_query_2
                                r * algebra::multiexp<typename CurveType::g1_type,
                                                      typename CurveType::scalar_field_type,
                                                      algebra::policies::multiexp_method_BDLO12<
                                                      typename CurveType::g1_type,
                                                      typename CurveType::scalar_field_type>>(
                                        proving_key.C_query_2.begin() + 1,
                                        proving_key.C_query_2.end(),
                                        sap_wit.coefficients_for_ACs.begin(),
                                        sap_wit.coefficients_for_ACs.end(),
                                        chunks) +
                                sap_wit.d2 * proving_key.G_gamma2_Z_t[0] +    // ZK-patch
                                algebra::multiexp<typename CurveType::g1_type,
                                                  typename CurveType::scalar_field_type,
                                                  algebra::policies::multiexp_method_BDLO12<
                                                  typename CurveType::g1_type,
                                                  typename CurveType::scalar_field_type>>(proving_key.G_gamma2_Z_t.begin(),
                                                                                   proving_key.G_gamma2_Z_t.end(),
                                                                                   sap_wit.coefficients_for_H.begin(),
                                                                                   sap_wit.coefficients_for_H.end(),
                                                                                   chunks);

                            proof_type proof = proof(std::move(A), std::move(B), std::move(C));
                            proof.print_size();

                            return proof;
                        }
                    };
                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_SE_PPZKSNARK_BASIC_PROVER_HPP
