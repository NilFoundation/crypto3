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

#ifndef CRYPTO3_RUN_RAM_PPZKSNARK_HPP
#define CRYPTO3_RUN_RAM_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/relations/ram_computations/rams/examples/ram_examples.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/ram_ppzksnark/ram_ppzksnark_params.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/ram_ppzksnark.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * The code below provides an example of all stages of running a RAM ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     architecture and bounds on the computation.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a boot trace, and an auxiliary input.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a boot trace, and a proof.
                 */
                template<typename CurveType>
                bool run_ram_ppzksnark(const ram_example<ram_ppzksnark_machine_pp<ram_ppzksnark_ppT>> &example) {
                    using basic_proof_system = ram_ppzksnark<CurveType>;

                    std::cout << "Call to run_ram_ppzksnark" << std::endl;

                    printf("This run uses an example with the following parameters:\n");
                    example.ap.print();
                    printf("* Primary input size bound (L): %zu\n", example.boot_trace_size_bound);
                    printf("* Time bound (T): %zu\n", example.time_bound);
                    printf("Hence, algebra::log2(L+2*T) equals %zu\n",
                           algebra::log2(example.boot_trace_size_bound + 2 * example.time_bound));

                    std::cout << "RAM ppzkSNARK Generator" << std::endl;
                    typename basic_proof_system::keypair_type keypair = generate<basic_proof_system>(
                        example.ap, example.boot_trace_size_bound, example.time_bound);

                    std::cout << "RAM ppzkSNARK Prover" << std::endl;
                    typename basic_proof_system::proof_type proof = prove<basic_proof_system>(
                        keypair.first, example.boot_trace, example.auxiliary_input);

                    std::cout << "RAM ppzkSNARK Verifier" << std::endl;
                    bool ans = verify<basic_proof_system>(keypair.second, example.boot_trace, proof);

                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_RAM_PPZKSNARK_HPP
