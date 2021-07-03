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
// @file Declaration of functionality that runs the R1CS GG-ppzkSNARK for
// a given R1CS example.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_GG_PPZKSNARK_MARSHALLING_HPP
#define CRYPTO3_RUN_R1CS_GG_PPZKSNARK_MARSHALLING_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include "../r1cs_examples.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ProofSystem>
                bool run_verifier_with_byte_input(std::vector<std::uint8_t> data) {
                    using proof_system_policy = ProofSystem;

                    typename nil::marshalling::verifier_data_from_bits<proof_system_policy>::verifier_data vd =
                        nil::marshalling::verifier_data_from_bits<proof_system_policy>::process(data);

                    std::cout << "Data converted from byte blob" << std::endl;

                    return verify<proof_system_policy>(vd.vk, vd.pi, vd.pr);
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
                bool run_r1cs_gg_ppzksnark_marshalling(
                    const r1cs_example<typename CurveType::scalar_field_type> &example) {

                    using proof_system_policy = r1cs_gg_ppzksnark<CurveType>;

                    std::cout << "Starting generator" << std::endl;

                    typename proof_system_policy::keypair_type keypair =
                        generate<proof_system_policy>(example.constraint_system);

                    std::cout << "Starting prover" << std::endl;

                    typename proof_system_policy::proof_type proof =
                        prove<proof_system_policy>(keypair.first, example.primary_input, example.auxiliary_input);

                    std::vector<std::uint8_t> data = nil::marshalling::verifier_data_to_bits<proof_system_policy>::process(
                        keypair.second, example.primary_input, proof);

                    std::cout << "Data converted to byte blob" << std::endl;

                    std::cout << "Starting verifier" << std::endl;

                    const bool ans = run_verifier_with_byte_input<proof_system_policy>(data);

                    std::cout << "Verifier finished, result: " << ans << std::endl;

                    return ans;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_GG_PPZKSNARK_MARSHALLING_HPP
