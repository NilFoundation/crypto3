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

#ifndef CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A prover algorithm for the R1CS ppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_prover {
                    typedef detail::r1cs_ppzksnark_policy<CurveType> policy_type;

                    using g1_type = typename CurveType::g1_type;
                    using g2_type = typename CurveType::g2_type;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using scalar_field_type = typename CurveType::scalar_field_type;

                public:
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline proof_type process(const proving_key_type &proving_key,
                                                     const primary_input_type &primary_input,
                                                     const auxiliary_input_type &auxiliary_input) {

                        const typename scalar_field_type::value_type d1 = algebra::random_element<scalar_field_type>(),
                                                                     d2 = algebra::random_element<scalar_field_type>(),
                                                                     d3 = algebra::random_element<scalar_field_type>();

                        const qap_witness<scalar_field_type> qap_wit =
                            reductions::r1cs_to_qap<scalar_field_type>::witness_map(proving_key.constraint_system, primary_input,
                                                                                    auxiliary_input, d1, d2, d3);

                        typename knowledge_commitment<g1_type, g1_type>::value_type g_A =
                            proving_key.A_query[0] + qap_wit.d1 * proving_key.A_query[qap_wit.num_variables + 1];
                        typename knowledge_commitment<g2_type, g1_type>::value_type g_B =
                            proving_key.B_query[0] + qap_wit.d2 * proving_key.B_query[qap_wit.num_variables + 1];
                        typename knowledge_commitment<g1_type, g1_type>::value_type g_C =
                            proving_key.C_query[0] + qap_wit.d3 * proving_key.C_query[qap_wit.num_variables + 1];

                        g1_value_type g_H = g1_value_type::zero();
                        g1_value_type g_K =
                            (proving_key.K_query[0] + qap_wit.d1 * proving_key.K_query[qap_wit.num_variables + 1] +
                             qap_wit.d2 * proving_key.K_query[qap_wit.num_variables + 2] +
                             qap_wit.d3 * proving_key.K_query[qap_wit.num_variables + 3]);
#ifdef MULTICORE
                        const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                             // var or call omp_set_num_threads()
#else
                        const std::size_t chunks = 1;
#endif

                        g_A = g_A + kc_multiexp_with_mixed_addition<algebra::policies::multiexp_method_bos_coster>(
                                        proving_key.A_query, 1, 1 + qap_wit.num_variables,
                                        qap_wit.coefficients_for_ABCs.begin(),
                                        qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables + 1, chunks);

                        g_B = g_B + kc_multiexp_with_mixed_addition<algebra::policies::multiexp_method_bos_coster>(
                                        proving_key.B_query, 1, 1 + qap_wit.num_variables,
                                        qap_wit.coefficients_for_ABCs.begin(),
                                        qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables + 1, chunks);

                        g_C = g_C + kc_multiexp_with_mixed_addition<algebra::policies::multiexp_method_bos_coster>(
                                        proving_key.C_query, 1, 1 + qap_wit.num_variables,
                                        qap_wit.coefficients_for_ABCs.begin(),
                                        qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables + 1, chunks);

                        g_H = g_H + algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                        proving_key.H_query.begin(), proving_key.H_query.begin() + qap_wit.degree + 1,
                                        qap_wit.coefficients_for_H.begin(),
                                        qap_wit.coefficients_for_H.begin() + qap_wit.degree + 1, chunks);

                        g_K =
                            g_K + algebra::multiexp_with_mixed_addition<algebra::policies::multiexp_method_bos_coster>(
                                      proving_key.K_query.begin() + 1,
                                      proving_key.K_query.begin() + 1 + qap_wit.num_variables,
                                      qap_wit.coefficients_for_ABCs.begin(),
                                      qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                        return proof_type(std::move(g_A), std::move(g_B), std::move(g_C), std::move(g_H),
                                          std::move(g_K));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
