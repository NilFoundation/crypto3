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

#ifndef CRYPTO3_RUN_R1CS_GG_PPZKSNARK_MARSHALLING_HPP
#define CRYPTO3_RUN_R1CS_GG_PPZKSNARK_MARSHALLING_HPP

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/policies/r1cs_gg_ppzksnark/generator.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/policies/r1cs_gg_ppzksnark/prover.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/policies/r1cs_gg_ppzksnark/verifier.hpp>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include "../r1cs_examples.hpp"

#include <nil/crypto3/zk/snark/algorithms/algorithms.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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
                bool run_r1cs_gg_ppzksnark_marshalling(const r1cs_example<typename CurveType::scalar_field_type> &example) {

                    using basic_proof_system = r1cs_gg_ppzksnark<CurveType>;

                    std::cout << "Starting generator" << std::endl;
                    typename r1cs_gg_ppzksnark<CurveType>::keypair_type keypair =
                        generator<basic_proof_system>(example.constraint_system);

                    std::cout << "Starting prover" << std::endl;

                    typename r1cs_gg_ppzksnark<CurveType>::proof_type proof = 
                        prover<basic_proof_system>(keypair.pk, example.primary_input, example.auxiliary_input);

                    std::vector<std::uint8_t> data =
                        snark::detail::verifier_data_to_bits<
                            basic_proof_system>::process(keypair.vk, example.primary_input, proof);

                    std::cout << "Data converted to byte blob" << std::endl;

                    typename snark::detail::verifier_data_from_bits<
                        basic_proof_system>::verifier_data vd = 
                        snark::detail::verifier_data_from_bits<
                        basic_proof_system>::process(data);

                    std::cout << "Data converted from byte blob" << std::endl;

                    BOOST_CHECK(vd.vk == keypair.vk);
                    BOOST_CHECK(vd.pi == example.primary_input);
                    BOOST_CHECK(vd.pr == proof);

                    std::cout << "Starting verifier" << std::endl;
                    
                    const bool ans = verifier<basic_proof_system>(vd.vk, vd.pi, vd.pr);

                    std::cout << "Verifier finished, result: " << ans << std::endl;

                    return ans;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_GG_PPZKSNARK_MARSHALLING_HPP
