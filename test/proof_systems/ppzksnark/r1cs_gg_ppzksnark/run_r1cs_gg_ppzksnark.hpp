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
// @file Declaration of functionality that runs the R1CS GG-ppzkSNARK for
// a given R1CS example.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_GG_PPZKSNARK_HPP
#define CRYPTO3_RUN_R1CS_GG_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

#include "r1cs_examples.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * R1CS example (specified by a constraint system, input, and witness).
                 */
                template<typename CurveType>
                bool run_r1cs_gg_ppzksnark(const r1cs_example<typename CurveType::scalar_field_type> &example);

                template<typename CurveType>
                typename std::enable_if<CurveType::has_affine_pairing, void>::type
                    test_affine_verifier(const typename r1cs_gg_ppzksnark<CurveType>::verification_key &vk,
                                         const typename r1cs_gg_ppzksnark<CurveType>::primary_input &primary_input,
                                         const typename r1cs_gg_ppzksnark<CurveType>::proof &proof,
                                         const bool expected_answer) {
                    const bool answer = r1cs_gg_ppzksnark<CurveType>::affine_verifier_weak_IC(vk, primary_input, proof);
                    BOOST_CHECK(answer == expected_answer);
                }

                template<typename CurveType>
                typename std::enable_if<!CurveType::has_affine_pairing, void>::type
                    test_affine_verifier(const typename r1cs_gg_ppzksnark<CurveType>::verification_key &vk,
                                         const typename r1cs_gg_ppzksnark<CurveType>::primary_input &primary_input,
                                         const typename r1cs_gg_ppzksnark<CurveType>::proof &proof,
                                         const bool expected_answer) {
                    BOOST_ATTRIBUTE_UNUSED(vk, primary_input, proof, expected_answer);
                }

                /**
                 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     constraint system CS to create a proving and a verification key for CS.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a primary input for CS, and an auxiliary input for CS.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a primary input for CS, and a proof.
                 */
                template<typename CurveType>
                bool run_r1cs_gg_ppzksnark(const r1cs_example<typename CurveType::scalar_field_type> &example) {
                    typename r1cs_gg_ppzksnark<CurveType>::keypair keypair =
                        r1cs_gg_ppzksnark<CurveType>::generator(example.constraint_system);

                    typename r1cs_gg_ppzksnark<CurveType>::processed_verification_key pvk =
                        r1cs_gg_ppzksnark<CurveType>::verifier_process_vk(keypair.vk);

                    typename r1cs_gg_ppzksnark<CurveType>::proof proof =
                        r1cs_gg_ppzksnark<CurveType>::prover(keypair.pk, example.primary_input, example.auxiliary_input);

                    const bool ans =
                        r1cs_gg_ppzksnark<CurveType>::verifier_strong_IC(keypair.vk, example.primary_input, proof);

                    const bool ans2 =
                        r1cs_gg_ppzksnark<CurveType>::online_verifier_strong_IC(pvk, example.primary_input, proof);
                    BOOST_CHECK(ans == ans2);

                    test_affine_verifier<CurveType>(keypair.vk, example.primary_input, proof, ans);

                    return ans;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_GG_PPZKSNARK_HPP
