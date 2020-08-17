//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef RUN_R1CS_PPZKADSNARK_HPP_
#define RUN_R1CS_PPZKADSNARK_HPP_

#include <nil/algebra/curves/public_params.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkADSNARK (generator, prover, and verifier) for a given
                 * R1CS example (specified by a constraint system, input, and witness).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename ppT>
                bool run_r1cs_ppzkadsnark(const r1cs_example<algebra::Fr<snark_pp<ppT>>> &example,
                                          const bool test_serialization);

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
                template<typename ppT>
                bool run_r1cs_ppzkadsnark(const r1cs_example<algebra::Fr<snark_pp<ppT>>> &example,
                                          const bool test_serialization) {
                    algebra::enter_block("Call to run_r1cs_ppzkadsnark");

                    r1cs_ppzkadsnark_auth_keys<ppT> auth_keys = r1cs_ppzkadsnark_auth_generator<ppT>();

                    algebra::print_header("R1CS ppzkADSNARK Generator");
                    r1cs_ppzkadsnark_keypair<ppT> keypair =
                        r1cs_ppzkadsnark_generator<ppT>(example.constraint_system, auth_keys.pap);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after generator");

                    algebra::print_header("Preprocess verification key");
                    r1cs_ppzkadsnark_processed_verification_key<ppT> pvk =
                        r1cs_ppzkadsnark_verifier_process_vk<ppT>(keypair.vk);

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of keys");
                        keypair.pk = algebra::reserialize<r1cs_ppzkadsnark_proving_key<ppT>>(keypair.pk);
                        keypair.vk = algebra::reserialize<r1cs_ppzkadsnark_verification_key<ppT>>(keypair.vk);
                        pvk = algebra::reserialize<r1cs_ppzkadsnark_processed_verification_key<ppT>>(pvk);
                        algebra::leave_block("Test serialization of keys");
                    }

                    algebra::print_header("R1CS ppzkADSNARK Authenticate");
                    std::vector<algebra::Fr<snark_pp<ppT>>> data;
                    data.reserve(example.constraint_system.num_inputs());
                    std::vector<labelT> labels;
                    labels.reserve(example.constraint_system.num_inputs());
                    for (std::size_t i = 0; i < example.constraint_system.num_inputs(); i++) {
                        labels.emplace_back(labelT());
                        data.emplace_back(example.primary_input[i]);
                    }
                    std::vector<r1cs_ppzkadsnark_auth_data<ppT>> auth_data =
                                                                     r1cs_ppzkadsnark_auth_sign<ppT>(data, auth_keys.sak, labels);

                    algebra::print_header("R1CS ppzkADSNARK Verify Symmetric");
                    bool auth_res = r1cs_ppzkadsnark_auth_verify<ppT>(data, auth_data, auth_keys.sak, labels);
                    printf("* The verification result is: %s\n", (auth_res ? "PASS" : "FAIL"));

                    algebra::print_header("R1CS ppzkADSNARK Verify Public");
                    bool auth_resp = r1cs_ppzkadsnark_auth_verify<ppT>(data, auth_data, auth_keys.pak, labels);
                    assert(auth_res == auth_resp);

                    algebra::print_header("R1CS ppzkADSNARK Prover");
                    r1cs_ppzkadsnark_proof<ppT> proof = r1cs_ppzkadsnark_prover<ppT>(
                        keypair.pk, example.primary_input, example.auxiliary_input, auth_data);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after prover");

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of proof");
                        proof = algebra::reserialize<r1cs_ppzkadsnark_proof<ppT>>(proof);
                        algebra::leave_block("Test serialization of proof");
                    }

                    algebra::print_header("R1CS ppzkADSNARK Symmetric Verifier");
                    bool ans = r1cs_ppzkadsnark_verifier<ppT>(keypair.vk, proof, auth_keys.sak, labels);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after verifier");
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    algebra::print_header("R1CS ppzkADSNARK Symmetric Online Verifier");
                    bool ans2 = r1cs_ppzkadsnark_online_verifier<ppT>(pvk, proof, auth_keys.sak, labels);
                    assert(ans == ans2);

                    algebra::print_header("R1CS ppzkADSNARK Public Verifier");
                    ans = r1cs_ppzkadsnark_verifier<ppT>(keypair.vk, auth_data, proof, auth_keys.pak, labels);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after verifier");
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    algebra::print_header("R1CS ppzkADSNARK Public Online Verifier");
                    ans2 = r1cs_ppzkadsnark_online_verifier<ppT>(pvk, auth_data, proof, auth_keys.pak, labels);
                    assert(ans == ans2);

                    algebra::leave_block("Call to run_r1cs_ppzkadsnark");

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RUN_R1CS_PPZKADSNARK_HPP_
