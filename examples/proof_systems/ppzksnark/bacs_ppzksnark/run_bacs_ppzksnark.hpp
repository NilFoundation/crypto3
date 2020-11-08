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

#ifndef CRYPTO3_RUN_BACS_PPZKSNARK_HPP
#define CRYPTO3_RUN_BACS_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/examples/bacs_examples.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * BACS example (specified by a circuit, primary input, and auxiliary input).
                 */
                template<typename CurveType>
                bool run_bacs_ppzksnark(const bacs_example<typename CurveType::scalar_field_type> &example);

                /**
                 * The code below provides an example of all stages of running a BACS ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     circuit C to create a proving and a verification key for C.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a primary input for C, and an auxiliary input for C.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a primary input for C, and a proof.
                 */
                template<typename CurveType>
                bool run_bacs_ppzksnark(const bacs_example<typename CurveType::scalar_field_type> &example) {
                    std::cout << "Call to run_bacs_ppzksnark" << std::endl;

                    std::cout << "BACS ppzkSNARK Generator" << std::endl;
                    typename bacs_ppzksnark<CurveType>::keypair_type keypair = bacs_ppzksnark<CurveType>::generator(example.circuit);

                    std::cout << "Preprocess verification key" << std::endl;
                    typename bacs_ppzksnark<CurveType>::processed_verification_key_type pvk =
                        bacs_ppzksnark<CurveType>::verifier_process_vk(keypair.vk);

                    std::cout << "BACS ppzkSNARK Prover" << std::endl;
                    typename bacs_ppzksnark<CurveType>::proof_type proof =
                        bacs_ppzksnark<CurveType>::prover(keypair.pk, example.primary_input, example.auxiliary_input);

                    std::cout << "BACS ppzkSNARK Verifier" << std::endl;
                    bool ans = bacs_ppzksnark<CurveType>::verifier_strong_input_consistency(keypair.vk, example.primary_input, proof);
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    std::cout << "BACS ppzkSNARK Online Verifier" << std::endl;
                    bool ans2 = bacs_ppzksnark<CurveType>::online_verifier_strong_input_consistency(pvk, example.primary_input, proof);
                    assert(ans == ans2);

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_BACS_PPZKSNARK_HPP
