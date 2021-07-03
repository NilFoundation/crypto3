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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_PROVER_HPP

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

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A prover algorithm for the R1CS GG-ppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                class r1cs_gg_ppzksnark_prover {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Basic> policy_type;

                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::g1_type g1_type;
                    typedef typename CurveType::g2_type g2_type;
                    typedef typename CurveType::gt_type gt_type;

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

                        BOOST_ASSERT(proving_key.constraint_system.is_satisfied(primary_input, auxiliary_input));

                        const qap_witness<scalar_field_type> qap_wit =
                            reductions::r1cs_to_qap<scalar_field_type>::witness_map(
                                proving_key.constraint_system, primary_input, auxiliary_input,
                                scalar_field_type::value_type::zero(), scalar_field_type::value_type::zero(),
                                scalar_field_type::value_type::zero());

                        /* We are dividing degree 2(d-1) polynomial by degree d polynomial
                           and not adding a PGHR-style ZK-patch, so our H is degree d-2 */
                        // BOOST_ASSERT(!qap_wit.coefficients_for_H[qap_wit.degree - 2].is_zero());
                        BOOST_ASSERT(qap_wit.coefficients_for_H[qap_wit.degree - 1].is_zero());
                        BOOST_ASSERT(qap_wit.coefficients_for_H[qap_wit.degree].is_zero());

                        /* Choose two random field elements for prover zero-knowledge. */
                        const typename scalar_field_type::value_type r = algebra::random_element<scalar_field_type>();
                        const typename scalar_field_type::value_type s = algebra::random_element<scalar_field_type>();
#ifdef MULTICORE
                        const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                             // var or call omp_set_num_threads()
#else
                        const std::size_t chunks = 1;
#endif

                        // TODO: sort out indexing
                        std::vector<typename scalar_field_type::value_type> const_padded_assignment(
                            1, scalar_field_type::value_type::one());
                        const_padded_assignment.insert(const_padded_assignment.end(),
                                                       qap_wit.coefficients_for_ABCs.begin(),
                                                       qap_wit.coefficients_for_ABCs.end());

                        typename g1_type::value_type evaluation_At =
                            algebra::multiexp_with_mixed_addition<algebra::policies::multiexp_method_BDLO12>(
                                proving_key.A_query.begin(),
                                proving_key.A_query.begin() + qap_wit.num_variables + 1,
                                const_padded_assignment.begin(),
                                const_padded_assignment.begin() + qap_wit.num_variables + 1,
                                chunks);

                        typename knowledge_commitment<g2_type, g1_type>::value_type evaluation_Bt =
                            kc_multiexp_with_mixed_addition<algebra::policies::multiexp_method_BDLO12>(
                                proving_key.B_query,
                                0,
                                qap_wit.num_variables + 1,
                                const_padded_assignment.begin(),
                                const_padded_assignment.begin() + qap_wit.num_variables + 1,
                                chunks);

                        typename g1_type::value_type evaluation_Ht =
                            algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                proving_key.H_query.begin(),
                                proving_key.H_query.begin() + (qap_wit.degree - 1),
                                qap_wit.coefficients_for_H.begin(),
                                qap_wit.coefficients_for_H.begin() + (qap_wit.degree - 1),
                                chunks);

                        typename g1_type::value_type evaluation_Lt =
                            algebra::multiexp_with_mixed_addition<algebra::policies::multiexp_method_BDLO12>(
                                proving_key.L_query.begin(),
                                proving_key.L_query.end(),
                                const_padded_assignment.begin() + qap_wit.num_inputs + 1,
                                const_padded_assignment.begin() + qap_wit.num_variables + 1,
                                chunks);

                        /* A = alpha + sum_i(a_i*A_i(t)) + r*delta */
                        typename g1_type::value_type g1_A =
                            proving_key.alpha_g1 + evaluation_At + r * proving_key.delta_g1;

                        /* B = beta + sum_i(a_i*B_i(t)) + s*delta */
                        typename g1_type::value_type g1_B =
                            proving_key.beta_g1 + evaluation_Bt.h + s * proving_key.delta_g1;
                        typename g2_type::value_type g2_B =
                            proving_key.beta_g2 + evaluation_Bt.g + s * proving_key.delta_g2;

                        /* C = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/delta) + A*s + r*b -
                         * r*s*delta
                         */
                        typename g1_type::value_type g1_C =
                            evaluation_Ht + evaluation_Lt + s * g1_A + r * g1_B - (r * s) * proving_key.delta_g1;

                        return proof_type(std::move(g1_A), std::move(g2_B), std::move(g1_C));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_PROVER_HPP
