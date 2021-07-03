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

#ifndef CRYPTO3_RUN_R1CS_PPZKADSNARK_HPP
#define CRYPTO3_RUN_R1CS_PPZKADSNARK_HPP

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using nil::crypto3::algebra;

                /**
                 * The code below provides an example of all stages of running a R1CS ppzkADSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkADSNARK generator on input a given
                 *     constraint system CS to create a proving and a verification key for CS.
                 * (2) The "prover", which runs the ppzkADSNARK prover on input the proving key,
                 *     a primary input for CS, and an auxiliary input for CS.
                 * (3) The "verifier", which runs the ppzkADSNARK verifier on input the verification key,
                 *     a primary input for CS, and a proof.
                 */
                template<typename CurveType>
                bool run_r1cs_ppzkadsnark(const r1cs_example<typename CurveType::scalar_field_type> &example) {

                    r1cs_ppzkadsnark_auth_keys<CurveType> auth_keys = r1cs_ppzkadsnark_auth_generator<CurveType>();

                    r1cs_ppzkadsnark_keypair<CurveType> keypair =
                        r1cs_ppzkadsnark_generator<CurveType>(example.constraint_system, auth_keys.pap);

                    r1cs_ppzkadsnark_processed_verification_key<CurveType> pvk =
                        r1cs_ppzkadsnark_process_verification_key<CurveType>(keypair.vk);

                    std::vector<typename CurveType::scalar_field_type::value_type> data;
                    data.reserve(example.constraint_system.num_inputs());
                    std::vector<label_type> labels;
                    labels.reserve(example.constraint_system.num_inputs());
                    for (std::size_t i = 0; i < example.constraint_system.num_inputs(); i++) {
                        labels.emplace_back(label_type());
                        data.emplace_back(example.primary_input[i]);
                    }
                    std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> auth_data =
                        r1cs_ppzkadsnark_auth_sign<CurveType>(data, auth_keys.sak, labels);

                    bool auth_res = r1cs_ppzkadsnark_auth_verify<CurveType>(data, auth_data, auth_keys.sak, labels);
                    printf("* The verification result is: %s\n", (auth_res ? "PASS" : "FAIL"));

                    bool auth_resp = r1cs_ppzkadsnark_auth_verify<CurveType>(data, auth_data, auth_keys.pak, labels);
                    assert(auth_res == auth_resp);

                    r1cs_ppzkadsnark_proof<CurveType> proof = r1cs_ppzkadsnark_prover<CurveType>(
                        keypair.pk, example.primary_input, example.auxiliary_input, auth_data);

                    bool ans = r1cs_ppzkadsnark_verifier<CurveType>(keypair.vk, proof, auth_keys.sak, labels);

                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    bool ans2 = r1cs_ppzkadsnark_online_verifier<CurveType>(pvk, proof, auth_keys.sak, labels);
                    assert(ans == ans2);

                    ans = r1cs_ppzkadsnark_verifier<CurveType>(keypair.vk, auth_data, proof, auth_keys.pak, labels);

                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    ans2 = r1cs_ppzkadsnark_online_verifier<CurveType>(pvk, auth_data, proof, auth_keys.pak, labels);
                    assert(ans == ans2);

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_PPZKADSNARK_HPP
