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

#ifndef CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

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
                        using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

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
                                d2 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                d3 = algebra::random_element<typename CurveType::scalar_field_type>();

                            const qap_witness<typename CurveType::scalar_field_type> qap_wit =
                                r1cs_to_qap<typename CurveType::scalar_field_type>::witness_map(
                                    proving_key.constraint_system, primary_input, auxiliary_input, d1, d2, d3);

                            knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A =
                                proving_key.A_query[0] + qap_wit.d1 * proving_key.A_query[qap_wit.num_variables + 1];
                            knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B =
                                proving_key.B_query[0] + qap_wit.d2 * proving_key.B_query[qap_wit.num_variables + 1];
                            knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C =
                                proving_key.C_query[0] + qap_wit.d3 * proving_key.C_query[qap_wit.num_variables + 1];

                            typename CurveType::g1_type::value_type g_H =
                                typename CurveType::g1_type::value_type::zero();
                            typename CurveType::g1_type::value_type g_K =
                                (proving_key.K_query[0] +
                                 qap_wit.d1 * proving_key.K_query[qap_wit.num_variables + 1] +
                                 qap_wit.d2 * proving_key.K_query[qap_wit.num_variables + 2] +
                                 qap_wit.d3 * proving_key.K_query[qap_wit.num_variables + 3]);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            g_A = g_A + kc_multiexp_with_mixed_addition<
                                            typename CurveType::g1_type, typename CurveType::g1_type,
                                            typename CurveType::scalar_field_type, 
                                            algebra::policies::multiexp_method_bos_coster<
                                            knowledge_commitment<
                                            typename CurveType::g1_type, typename CurveType::g1_type>, 
                                            typename CurveType::scalar_field_type>>(
                                            proving_key.A_query, 1, 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            g_B = g_B + kc_multiexp_with_mixed_addition<
                                            typename CurveType::g2_type, typename CurveType::g1_type,
                                            typename CurveType::scalar_field_type, 
                                            algebra::policies::multiexp_method_bos_coster<
                                            knowledge_commitment<
                                            typename CurveType::g2_type, typename CurveType::g1_type>, 
                                            typename CurveType::scalar_field_type>>(
                                            proving_key.B_query, 1, 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            g_C = g_C + kc_multiexp_with_mixed_addition<
                                            typename CurveType::g1_type, typename CurveType::g1_type,
                                            typename CurveType::scalar_field_type, 
                                            algebra::policies::multiexp_method_bos_coster<
                                            knowledge_commitment<
                                            typename CurveType::g1_type, typename CurveType::g1_type>, 
                                            typename CurveType::scalar_field_type>>(
                                            proving_key.C_query, 1, 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            g_H = g_H +
                                  algebra::multiexp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                    algebra::policies::multiexp_method_BDLO12<
                                                    typename CurveType::g1_type, typename CurveType::scalar_field_type>>(
                                      proving_key.H_query.begin(), proving_key.H_query.begin() + qap_wit.degree + 1,
                                      qap_wit.coefficients_for_H.begin(),
                                      qap_wit.coefficients_for_H.begin() + qap_wit.degree + 1, chunks);

                            g_K = g_K + algebra::multiexp_with_mixed_addition<typename CurveType::g1_type,
                                                                              typename CurveType::scalar_field_type,
                                                                              algebra::policies::multiexp_method_bos_coster<
                                                                              typename CurveType::g1_type,
                                                                              typename CurveType::scalar_field_type>>(
                                            proving_key.K_query.begin() + 1,
                                            proving_key.K_query.begin() + 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            proof_type proof =
                                proof(std::move(g_A), std::move(g_B), std::move(g_C), std::move(g_H), std::move(g_K));
                            proof.print_size();

                            return proof;
                        }
                    };
                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
