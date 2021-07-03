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

#ifndef CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_PROVER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A prover algorithm for the USCS ppzkSNARK.
                 *
                 * Given a USCS primary input X and a USCS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the USCS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_prover {
                    typedef detail::uscs_ppzksnark_policy<CurveType> policy_type;

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

                        const typename CurveType::scalar_field_type::value_type d =
                            algebra::random_element<typename CurveType::scalar_field_type>();

                        const ssp_witness<typename CurveType::scalar_field_type> ssp_wit =
                            reductions::uscs_to_ssp<typename CurveType::scalar_field_type>::witness_map(
                                proving_key.constraint_system, primary_input, auxiliary_input, d);

                        /* sanity checks */
                        assert(proving_key.constraint_system.is_satisfied(primary_input, auxiliary_input));
                        assert(proving_key.V_g1_query.size() == ssp_wit.num_variables + 2 - ssp_wit.num_inputs - 1);
                        assert(proving_key.alpha_V_g1_query.size() ==
                               ssp_wit.num_variables + 2 - ssp_wit.num_inputs - 1);
                        assert(proving_key.H_g1_query.size() == ssp_wit.degree + 1);
                        assert(proving_key.V_g2_query.size() == ssp_wit.num_variables + 2);

                        typename CurveType::g1_type::value_type V_g1 =
                            ssp_wit.d * proving_key.V_g1_query[proving_key.V_g1_query.size() - 1];
                        typename CurveType::g1_type::value_type alpha_V_g1 =
                            ssp_wit.d * proving_key.alpha_V_g1_query[proving_key.alpha_V_g1_query.size() - 1];
                        typename CurveType::g1_type::value_type H_g1 = CurveType::g1_type::value_type::zero();
                        typename CurveType::g2_type::value_type V_g2 =
                            proving_key.V_g2_query[0] +
                            ssp_wit.d * proving_key.V_g2_query[proving_key.V_g2_query.size() - 1];

#ifdef MULTICORE
                        const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                             // var or call omp_set_num_threads()
#else
                        const std::size_t chunks = 1;
#endif

                        // MAYBE LATER: do queries 1,2,4 at once for slightly better speed

                        V_g1 = V_g1 + algebra::multiexp_with_mixed_addition<algebra::policies::multiexp_method_BDLO12>(
                                          proving_key.V_g1_query.begin(),
                                          proving_key.V_g1_query.begin() + (ssp_wit.num_variables - ssp_wit.num_inputs),
                                          ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_inputs,
                                          ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_variables, chunks);

                        alpha_V_g1 =
                            alpha_V_g1 +
                            algebra::multiexp_with_mixed_addition<algebra::policies::multiexp_method_BDLO12>(
                                proving_key.alpha_V_g1_query.begin(),
                                proving_key.alpha_V_g1_query.begin() + (ssp_wit.num_variables - ssp_wit.num_inputs),
                                ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_inputs,
                                ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_variables, chunks);

                        H_g1 = H_g1 + algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                          proving_key.H_g1_query.begin(),
                                          proving_key.H_g1_query.begin() + ssp_wit.degree + 1,
                                          ssp_wit.coefficients_for_H.begin(),
                                          ssp_wit.coefficients_for_H.begin() + ssp_wit.degree + 1, chunks);

                        V_g2 = V_g2 + algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                          proving_key.V_g2_query.begin() + 1,
                                          proving_key.V_g2_query.begin() + ssp_wit.num_variables + 1,
                                          ssp_wit.coefficients_for_Vs.begin(),
                                          ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_variables, chunks);

                        proof_type proof =
                            proof_type(std::move(V_g1), std::move(alpha_V_g1), std::move(H_g1), std::move(V_g2));

                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_GENERATOR_HPP
