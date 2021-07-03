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

#ifndef CRYPTO3_ZK_RUN_BACS_PPZKSNARK_HPP
#define CRYPTO3_ZK_RUN_BACS_PPZKSNARK_HPP

#include "bacs_examples.hpp"

#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark.hpp>

#include "../r1cs_examples.hpp"

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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

                    using basic_proof_system = bacs_ppzksnark<CurveType>;
                    
                    std::cout << "Call to run_bacs_ppzksnark" << std::endl;

                    std::cout << "BACS ppzkSNARK Generator" << std::endl;
                    typename basic_proof_system::keypair_type keypair =
                        generate<basic_proof_system>(example.circuit);

                    std::cout << "Preprocess verification key" << std::endl;
                    typename basic_proof_system::processed_verification_key_type pvk =
                        bacs_ppzksnark_process_verification_key<CurveType>::process(keypair.second);

                    std::cout << "BACS ppzkSNARK Prover" << std::endl;
                    typename basic_proof_system::proof_type proof =
                        prove<basic_proof_system>(keypair.first, example.primary_input, example.auxiliary_input);

                    std::cout << "BACS ppzkSNARK Verifier" << std::endl;
                    bool ans = verify<basic_proof_system>(keypair.second, example.primary_input, proof);
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    std::cout << "BACS ppzkSNARK Online Verifier" << std::endl;
                    bool ans2 = verify<basic_proof_system>(pvk, example.primary_input, proof);
                    BOOST_CHECK(ans == ans2);

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_BACS_PPZKSNARK_HPP
